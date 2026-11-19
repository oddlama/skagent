//! The socket for age requests: who is answered what, on it and on the
//! ssh-agent socket. What needs a security key is in the VM test.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use skagent::age::AgeIdentities;
use skagent::agent::SkAgent;
use skagent::identities::IdentityStore;
use skagent::peer::{FileId, OwnPrograms};
use skagent::serve::{Listening, serve_sockets_until};
use skagent::signer::Signer;
use skagent_age::wire::{
    self, LIST_EXTENSION, ListReply, NEW_EXTENSION, Refusal, UNWRAP_EXTENSION, UnwrapReply,
    UnwrapRequest,
};
use skagent_age::{FileKey, Identity, Recipient, Seed};
use skagent_fido::AgeCredential;
use ssh_agent_lib::agent::Session as _;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::extension::QueryResponse;
use ssh_agent_lib::proto::{Extension, Unparsed};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Which of skagent's programs the agent takes this test for.
#[derive(Clone, Copy)]
enum TakenFor {
    Agent,
    Plugin,
    Stranger,
}

struct Running {
    ssh: PathBuf,
    age: PathBuf,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<()>>,
    _directory: tempfile::TempDir,
}

fn recipient(byte: u8) -> Result<Recipient> {
    Seed::from_bytes(&[byte; 32])?.recipient()
}

impl Running {
    /// An agent with both sockets, knowing `identities`: credentials
    /// numbered by a byte, with or without a known recipient.
    async fn start(taken_for: TakenFor, identities: &[(u8, bool)]) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let ssh = directory.path().join("agent.sock");
        let age = directory.path().join("agent-age.sock");
        let this = FileId::of(Path::new("/proc/self/exe"))?;
        let other_file = directory.path().join("other");
        std::fs::write(&other_file, "x")?;
        let other = FileId::of(&other_file)?;
        let own = match taken_for {
            TakenFor::Agent => OwnPrograms::new(this, Some(other)),
            TakenFor::Plugin => OwnPrograms::new(other, Some(this)),
            TakenFor::Stranger => OwnPrograms::new(other, None),
        };
        let mut known = AgeIdentities::default();
        for &(byte, derived) in identities {
            let credential = AgeCredential::new(vec![byte; 32])?;
            known.found(std::slice::from_ref(&credential));
            if derived {
                known.derived(&credential, &recipient(byte)?);
            }
        }
        let agent = SkAgent::with_stores(
            Signer::default(),
            IdentityStore::default(),
            known,
            Some(own),
        );
        let (shutdown, shutdown_received) = oneshot::channel::<()>();
        let (ssh_path, age_path) = (ssh.clone(), age.clone());
        let task = tokio::spawn(async move {
            serve_sockets_until(
                Listening::Bind(ssh_path),
                Some(Listening::Bind(age_path)),
                agent,
                async move {
                    shutdown_received
                        .await
                        .context("shutdown sender dropped before signalling")
                },
            )
            .await
        });
        tokio::time::timeout(support::TIMEOUT, async {
            while !(ssh.exists() && age.exists()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("the agent's sockets did not appear")?;
        Ok(Self {
            ssh,
            age,
            shutdown,
            task,
            _directory: directory,
        })
    }

    async fn client(path: &Path) -> Result<Client<UnixStream>> {
        Ok(Client::new(UnixStream::connect(path).await?))
    }

    /// One extension request on the socket at `path`: the reply's details,
    /// or `None` if the agent answered with a failure.
    async fn ask(path: &Path, name: &str, details: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let mut client = Self::client(path).await?;
        let reply = client
            .extension(Extension {
                name: name.to_owned(),
                details: Unparsed::from(details),
            })
            .await;
        match reply {
            Ok(Some(extension)) => {
                ensure!(extension.name == name, "answered as {}", extension.name);
                Ok(Some(extension.details.into_bytes()))
            }
            Ok(None) => bail!("{name} was answered with a bare success"),
            Err(_) => Ok(None),
        }
    }

    async fn unwrap(&self, path: &Path, identity: Identity) -> Result<Option<UnwrapReply>> {
        let stanza = recipient(1)?.wrap(&FileKey::from_bytes(b"0123456789abcdef")?, &[1; 64])?;
        let request = UnwrapRequest {
            identity,
            stanzas: vec![stanza],
        };
        Self::ask(path, UNWRAP_EXTENSION, request.encode()?)
            .await?
            .map(|details| UnwrapReply::decode(&details))
            .transpose()
    }

    async fn stop(self) -> Result<()> {
        self.shutdown
            .send(())
            .map_err(|()| anyhow!("agent task ended before shutdown"))?;
        tokio::time::timeout(support::TIMEOUT, self.task)
            .await
            .context("agent did not stop in time")?
            .context("agent task panicked or was cancelled")??;
        ensure!(
            !self.ssh.exists() && !self.age.exists(),
            "a socket was left behind"
        );
        Ok(())
    }
}

fn refused(reply: Option<UnwrapReply>) -> Result<Refusal> {
    match reply {
        Some(UnwrapReply::Refused(refusal)) => Ok(refusal),
        other => bail!("not refused: {other:?}"),
    }
}

#[tokio::test]
async fn the_command_line_may_list_and_create_but_not_decrypt() -> Result<()> {
    let agent = Running::start(TakenFor::Agent, &[(1, true), (2, false)]).await?;
    let listed = Running::ask(&agent.age, LIST_EXTENSION, wire::simple_request())
        .await?
        .context("the list was refused")?;
    ensure!(ListReply::decode(&listed)?.identities == [Some(recipient(1)?), None]);
    // The plugin's request, from the wrong program: refused before anything.
    ensure!(refused(agent.unwrap(&agent.age, Identity::AtHand).await?)? == Refusal::NotAllowed);
    // Malformed requests are failures.
    for details in [vec![], vec![2], vec![1, 0]] {
        ensure!(
            Running::ask(&agent.age, LIST_EXTENSION, details)
                .await?
                .is_none(),
            "a malformed list request was answered"
        );
    }
    for details in [vec![], vec![1], vec![1, 2], vec![2, 0]] {
        ensure!(
            Running::ask(&agent.age, NEW_EXTENSION, details)
                .await?
                .is_none(),
            "a malformed request for a new identity was answered"
        );
    }
    agent.stop().await
}

#[tokio::test]
async fn the_plugin_may_ask_for_file_keys_and_nothing_else() -> Result<()> {
    let agent = Running::start(TakenFor::Plugin, &[]).await?;
    ensure!(
        Running::ask(&agent.age, LIST_EXTENSION, wire::simple_request())
            .await?
            .is_none(),
        "the plugin listed identities"
    );
    ensure!(
        Running::ask(&agent.age, NEW_EXTENSION, wire::new_request(false))
            .await?
            .is_none(),
        "the plugin created an identity"
    );
    // Its own request is answered: here, that there is no identity.
    ensure!(refused(agent.unwrap(&agent.age, Identity::AtHand).await?)? == Refusal::NoIdentity);
    ensure!(
        refused(
            agent
                .unwrap(&agent.age, Identity::Named(recipient(1)?))
                .await?
        )? == Refusal::NoIdentity
    );
    // A malformed one is a failure, not a reply.
    ensure!(
        Running::ask(&agent.age, UNWRAP_EXTENSION, vec![1, 0, 0])
            .await?
            .is_none()
    );
    agent.stop().await
}

#[tokio::test]
async fn which_identity_is_meant_is_settled_before_any_security_key_is_asked() -> Result<()> {
    // Two identities nothing tells apart: no security key is at hand here,
    // and none is waited for.
    let agent = Running::start(TakenFor::Plugin, &[(1, false), (2, false)]).await?;
    ensure!(refused(agent.unwrap(&agent.age, Identity::AtHand).await?)? == Refusal::Ambiguous);
    ensure!(
        refused(
            agent
                .unwrap(&agent.age, Identity::Named(recipient(9)?))
                .await?
        )? == Refusal::Ambiguous
    );
    agent.stop().await?;

    // Every identity's recipient is known, and the one named is none of them.
    let agent = Running::start(TakenFor::Plugin, &[(1, true), (2, true)]).await?;
    ensure!(
        refused(
            agent
                .unwrap(&agent.age, Identity::Named(recipient(9)?))
                .await?
        )? == Refusal::NoIdentity
    );
    ensure!(refused(agent.unwrap(&agent.age, Identity::AtHand).await?)? == Refusal::Ambiguous);
    agent.stop().await
}

#[tokio::test]
async fn a_locked_agent_answers_no_age_request() -> Result<()> {
    let agent = Running::start(TakenFor::Plugin, &[(1, true)]).await?;
    Running::client(&agent.ssh)
        .await?
        .lock("passphrase".to_owned())
        .await
        .map_err(|error| anyhow!("locking: {error}"))?;
    ensure!(refused(agent.unwrap(&agent.age, Identity::AtHand).await?)? == Refusal::Locked);
    ensure!(
        refused(
            agent
                .unwrap(&agent.age, Identity::Named(recipient(1)?))
                .await?
        )? == Refusal::Locked
    );
    agent.stop().await?;

    let agent = Running::start(TakenFor::Agent, &[(1, true)]).await?;
    Running::client(&agent.ssh)
        .await?
        .lock("passphrase".to_owned())
        .await
        .map_err(|error| anyhow!("locking: {error}"))?;
    ensure!(
        Running::ask(&agent.age, LIST_EXTENSION, wire::simple_request())
            .await?
            .is_none()
    );
    ensure!(
        Running::ask(&agent.age, NEW_EXTENSION, wire::new_request(false))
            .await?
            .is_none()
    );
    agent.stop().await
}

#[tokio::test]
async fn a_stranger_is_answered_nothing() -> Result<()> {
    let agent = Running::start(TakenFor::Stranger, &[(1, true)]).await?;
    ensure!(refused(agent.unwrap(&agent.age, Identity::AtHand).await?)? == Refusal::NotAllowed);
    ensure!(
        Running::ask(&agent.age, LIST_EXTENSION, wire::simple_request())
            .await?
            .is_none()
    );
    ensure!(
        Running::ask(&agent.age, NEW_EXTENSION, wire::new_request(true))
            .await?
            .is_none()
    );
    agent.stop().await
}

#[tokio::test]
async fn the_socket_for_age_requests_speaks_no_ssh_agent_protocol() -> Result<()> {
    let agent = Running::start(TakenFor::Agent, &[]).await?;
    let mut client = Running::client(&agent.age).await?;
    ensure!(client.request_identities().await.is_err(), "listed keys");
    ensure!(
        client
            .add_identity(support::add_sk(1, "key")?)
            .await
            .is_err(),
        "added a key"
    );
    ensure!(
        client.remove_all_identities().await.is_err(),
        "removed keys"
    );
    ensure!(
        client.lock("passphrase".to_owned()).await.is_err(),
        "locked"
    );
    for name in [
        "forget-pins@skagent",
        "load-resident-keys@skagent",
        "unknown@example",
    ] {
        ensure!(
            Running::ask(&agent.age, name, Vec::new()).await?.is_none(),
            "{name} was answered"
        );
    }
    // The ssh-agent socket still does all of that.
    let mut ssh = Running::client(&agent.ssh).await?;
    ssh.add_identity(support::add_sk(1, "key")?)
        .await
        .map_err(|error| anyhow!("adding on the ssh-agent socket: {error}"))?;
    ensure!(
        ssh.request_identities()
            .await
            .map_err(|error| anyhow!("{error}"))?
            .len()
            == 1
    );
    agent.stop().await
}

#[tokio::test]
async fn a_connection_bound_to_an_ssh_session_is_forwarded_and_gets_nothing_more() -> Result<()> {
    let agent = Running::start(TakenFor::Agent, &[(1, true)]).await?;
    let mut client = Running::client(&agent.age).await?;
    let list = || Extension {
        name: LIST_EXTENSION.to_owned(),
        details: Unparsed::from(wire::simple_request()),
    };
    ensure!(
        client.extension(list()).await.is_ok(),
        "the list before the bind"
    );
    // Whatever it carries: none of skagent's programs binds a session.
    let bind = Extension {
        name: "session-bind@openssh.com".to_owned(),
        details: Unparsed::from(vec![0; 8]),
    };
    ensure!(
        client.extension(bind).await.is_err(),
        "the bind was accepted"
    );
    ensure!(
        client.extension(list()).await.is_err(),
        "the list after the bind"
    );
    agent.stop().await
}

#[tokio::test]
async fn the_ssh_agent_socket_answers_no_age_request() -> Result<()> {
    let agent = Running::start(TakenFor::Plugin, &[(1, true)]).await?;
    ensure!(
        agent.unwrap(&agent.ssh, Identity::AtHand).await?.is_none(),
        "unwrapped"
    );
    for (name, details) in [
        (LIST_EXTENSION, wire::simple_request()),
        (NEW_EXTENSION, wire::new_request(false)),
    ] {
        ensure!(
            Running::ask(&agent.ssh, name, details).await?.is_none(),
            "{name} was answered on the ssh-agent socket"
        );
    }
    agent.stop().await
}

#[tokio::test]
async fn each_socket_names_its_own_extensions() -> Result<()> {
    let agent = Running::start(TakenFor::Agent, &[]).await?;
    let query = |path: PathBuf| async move {
        let details = Running::ask(&path, "query", Vec::new())
            .await?
            .context("the query was refused")?;
        let response: QueryResponse = Unparsed::from(details)
            .parse()
            .map_err(|error| anyhow!("decoding the query's answer: {error}"))?;
        Ok::<_, anyhow::Error>(response.extensions)
    };
    let age = query(agent.age.clone()).await?;
    ensure!(
        age == ["query", UNWRAP_EXTENSION, NEW_EXTENSION, LIST_EXTENSION],
        "{age:?}"
    );
    let ssh = query(agent.ssh.clone()).await?;
    ensure!(ssh.iter().all(|name| !name.starts_with("age-")), "{ssh:?}");
    ensure!(
        ssh.contains(&"session-bind@openssh.com".to_owned()),
        "{ssh:?}"
    );
    agent.stop().await
}
