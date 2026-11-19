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
    self, BATCH_EXTENSION, BatchReply, BatchRequest, LIST_EXTENSION, ListReply, NEW_EXTENSION,
    Refusal, UNWRAP_EXTENSION, UnwrapReply, UnwrapRequest,
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
    /// The agent that is served, to look at what the sockets don't show.
    agent: SkAgent,
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
        Self::start_with(taken_for, identities, Signer::default()).await
    }

    /// [`Running::start`], with the agent using `signer`.
    async fn start_with(
        taken_for: TakenFor,
        identities: &[(u8, bool)],
        signer: Signer,
    ) -> Result<Self> {
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
        let agent = SkAgent::with_stores(signer, IdentityStore::default(), known, Some(own));
        let served = agent.clone();
        let (shutdown, shutdown_received) = oneshot::channel::<()>();
        let (ssh_path, age_path) = (ssh.clone(), age.clone());
        let task = tokio::spawn(async move {
            serve_sockets_until(
                Listening::Bind(ssh_path),
                Some(Listening::Bind(age_path)),
                served,
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
            agent,
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
        (BATCH_EXTENSION, batch_request(0)?),
    ] {
        ensure!(
            Running::ask(&agent.ssh, name, details).await?.is_none(),
            "{name} was answered on the ssh-agent socket"
        );
    }
    ensure!(agent.agent.signer().running_batches().await == 0);
    agent.stop().await
}

#[tokio::test]
async fn with_age_forwarding_the_ssh_agent_socket_decrypts_and_nothing_more() -> Result<()> {
    let agent = Running::start(TakenFor::Stranger, &[]).await?;
    let query = || async {
        let details = Running::ask(&agent.ssh, "query", Vec::new())
            .await?
            .context("the query was refused")?;
        let response: QueryResponse = Unparsed::from(details)
            .parse()
            .map_err(|error| anyhow!("decoding the query's answer: {error}"))?;
        Ok::<_, anyhow::Error>(response.extensions)
    };
    ensure!(!query().await?.contains(&UNWRAP_EXTENSION.to_owned()));
    ensure!(
        agent.unwrap(&agent.ssh, Identity::AtHand).await?.is_none(),
        "unwrapped without being allowed to"
    );

    agent.agent.allow_age_forwarding(true);
    ensure!(query().await?.contains(&UNWRAP_EXTENSION.to_owned()));
    // Taken, whoever asks: here, answered that there is no identity.
    ensure!(refused(agent.unwrap(&agent.ssh, Identity::AtHand).await?)? == Refusal::NoIdentity);
    // A malformed request is a failure.
    ensure!(
        Running::ask(&agent.ssh, UNWRAP_EXTENSION, vec![1, 0, 0])
            .await?
            .is_none()
    );
    // Identities stay this machine's business, and so do batches.
    for (name, details) in [
        (LIST_EXTENSION, wire::simple_request()),
        (NEW_EXTENSION, wire::new_request(false)),
        (BATCH_EXTENSION, batch_request(0)?),
    ] {
        ensure!(
            Running::ask(&agent.ssh, name, details).await?.is_none(),
            "{name} was answered on the ssh-agent socket"
        );
    }
    ensure!(agent.agent.signer().running_batches().await == 0);
    // The socket for age requests is as it was: no stranger there.
    ensure!(refused(agent.unwrap(&agent.age, Identity::AtHand).await?)? == Refusal::NotAllowed);

    agent.agent.allow_age_forwarding(false);
    ensure!(agent.unwrap(&agent.ssh, Identity::AtHand).await?.is_none());
    agent.stop().await?;

    // A locked agent decrypts for nobody.
    let agent = Running::start(TakenFor::Stranger, &[(1, true)]).await?;
    agent.agent.allow_age_forwarding(true);
    Running::client(&agent.ssh)
        .await?
        .lock("passphrase".to_owned())
        .await
        .map_err(|error| anyhow!("locking: {error}"))?;
    ensure!(refused(agent.unwrap(&agent.ssh, Identity::AtHand).await?)? == Refusal::Locked);
    agent.stop().await
}

/// The details of a request for a batch of `seconds` (zero: as long as
/// allowed) for the command `agenix rekey`.
fn batch_request(seconds: u32) -> Result<Vec<u8>> {
    BatchRequest {
        seconds,
        command: "agenix rekey".to_owned(),
    }
    .encode()
}

/// Asks for a batch on `client`'s connection: how long it lasts, or `None`
/// if the agent refused.
async fn open_batch(client: &mut Client<UnixStream>, seconds: u32) -> Result<Option<u32>> {
    let reply = client
        .extension(Extension {
            name: BATCH_EXTENSION.to_owned(),
            details: Unparsed::from(batch_request(seconds)?),
        })
        .await;
    match reply {
        Ok(Some(extension)) => {
            ensure!(extension.name == BATCH_EXTENSION);
            Ok(Some(
                BatchReply::decode(extension.details.as_ref())?.seconds,
            ))
        }
        Ok(None) => bail!("a batch was answered with a bare success"),
        Err(_) => Ok(None),
    }
}

/// Waits until the agent has `running` batches running.
async fn batches_running(agent: &Running, running: usize) -> Result<()> {
    tokio::time::timeout(support::TIMEOUT, async {
        while agent.agent.signer().running_batches().await != running {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .with_context(|| format!("never {running} batches running"))
}

/// Whether the kernel pins the peers of connections (Linux 6.5). Without
/// that there are no batches.
fn peers_are_pinned() -> Result<bool> {
    let (one, _other) = std::os::unix::net::UnixStream::pair()?;
    Ok(skagent_fds::peer_pidfd(std::os::fd::AsFd::as_fd(&one))?.is_some())
}

#[tokio::test]
async fn the_command_line_gets_a_batch_that_lasts_as_long_as_its_connection() -> Result<()> {
    let agent = Running::start(TakenFor::Agent, &[(1, true)]).await?;
    let mut tool = Running::client(&agent.age).await?;
    if !peers_are_pinned()? {
        ensure!(
            open_batch(&mut tool, 0).await?.is_none(),
            "a batch nobody can be proven in"
        );
        return agent.stop().await;
    }
    // As long as the agent allows, unless less is asked for.
    ensure!(open_batch(&mut tool, 0).await? == Some(600));
    batches_running(&agent, 1).await?;
    ensure!(
        open_batch(&mut tool, 0).await?.is_none(),
        "a second batch on one connection"
    );
    let mut shorter = Running::client(&agent.age).await?;
    ensure!(open_batch(&mut shorter, 60).await? == Some(60));
    let mut longer = Running::client(&agent.age).await?;
    ensure!(
        open_batch(&mut longer, 6000).await? == Some(600),
        "longer than allowed"
    );
    batches_running(&agent, 3).await?;
    ensure!(
        agent.agent.signer().kept_seeds().await == 0,
        "a seed before any decryption"
    );

    // The tool is gone when its connection is: so is its batch.
    drop(shorter);
    batches_running(&agent, 2).await?;
    drop(tool);
    drop(longer);
    batches_running(&agent, 0).await?;

    // A malformed request opens none.
    for details in [
        vec![],
        vec![1],
        vec![2, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 0],
    ] {
        ensure!(
            Running::ask(&agent.age, BATCH_EXTENSION, details)
                .await?
                .is_none(),
            "a malformed request for a batch was answered"
        );
    }
    ensure!(agent.agent.signer().running_batches().await == 0);
    agent.stop().await
}

#[tokio::test]
async fn only_the_command_line_gets_a_batch() -> Result<()> {
    for taken_for in [TakenFor::Plugin, TakenFor::Stranger] {
        let agent = Running::start(taken_for, &[(1, true)]).await?;
        let mut client = Running::client(&agent.age).await?;
        ensure!(
            open_batch(&mut client, 0).await?.is_none(),
            "a batch for another program"
        );
        ensure!(agent.agent.signer().running_batches().await == 0);
        agent.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_batch_ends_when_its_time_is_up() -> Result<()> {
    if !peers_are_pinned()? {
        return Ok(());
    }
    let agent = Running::start(TakenFor::Agent, &[(1, true)]).await?;
    let mut tool = Running::client(&agent.age).await?;
    ensure!(open_batch(&mut tool, 1).await? == Some(1));
    ensure!(agent.agent.signer().running_batches().await == 1);
    // Nobody asks it anything: the agent ends it by itself.
    batches_running(&agent, 0).await?;
    drop(tool);
    agent.stop().await
}

#[tokio::test]
async fn whatever_evicts_pins_ends_batches() -> Result<()> {
    if !peers_are_pinned()? {
        return Ok(());
    }
    let agent = Running::start(TakenFor::Agent, &[(1, true)]).await?;
    let signer = agent.agent.signer();
    let open = || async {
        let mut tool = Running::client(&agent.age).await?;
        ensure!(open_batch(&mut tool, 0).await?.is_some(), "no batch");
        ensure!(signer.running_batches().await == 1);
        Ok(tool)
    };

    // `skagent forget`.
    let tool = open().await?;
    Running::client(&agent.ssh)
        .await?
        .extension(Extension {
            name: "forget-pins@skagent".to_owned(),
            details: Unparsed::from(Vec::new()),
        })
        .await
        .map_err(|error| anyhow!("forgetting PINs: {error}"))?;
    ensure!(
        signer.running_batches().await == 0,
        "running after a forget"
    );
    drop(tool);

    // `ssh-add -D`.
    let tool = open().await?;
    Running::client(&agent.ssh)
        .await?
        .remove_all_identities()
        .await
        .map_err(|error| anyhow!("removing all keys: {error}"))?;
    ensure!(
        signer.running_batches().await == 0,
        "running after removing all keys"
    );
    drop(tool);

    // The screen locks.
    let tool = open().await?;
    agent.agent.forget_pins("the screen locked").await;
    ensure!(signer.running_batches().await == 0, "running after a lock");
    drop(tool);

    // Lock and sleep events can't be watched any more, or not yet again.
    agent.agent.set_caching_available(true).await;
    let tool = open().await?;
    agent.agent.set_caching_available(false).await;
    ensure!(
        signer.running_batches().await == 0,
        "running without monitoring"
    );
    drop(tool);
    agent.agent.set_caching_available(true).await;
    let tool = open().await?;
    agent.agent.caching_pending().await;
    ensure!(
        signer.running_batches().await == 0,
        "running while monitoring restarts"
    );
    drop(tool);

    // `ssh-add -x`: over, and none is opened while the agent is locked.
    let tool = open().await?;
    let mut ssh = Running::client(&agent.ssh).await?;
    ssh.lock("passphrase".to_owned())
        .await
        .map_err(|error| anyhow!("locking: {error}"))?;
    ensure!(
        signer.running_batches().await == 0,
        "running in a locked agent"
    );
    drop(tool);
    let mut tool = Running::client(&agent.age).await?;
    ensure!(
        open_batch(&mut tool, 0).await?.is_none(),
        "a batch from a locked agent"
    );
    ssh.unlock("passphrase".to_owned())
        .await
        .map_err(|error| anyhow!("unlocking: {error}"))?;
    ensure!(
        open_batch(&mut tool, 0).await?.is_some(),
        "no batch after unlocking"
    );
    agent.stop().await
}

#[tokio::test]
async fn batches_can_be_turned_off() -> Result<()> {
    let signer = Signer::default().with_batch_lifetime(Duration::ZERO);
    let agent = Running::start_with(TakenFor::Agent, &[(1, true)], signer).await?;
    let mut tool = Running::client(&agent.age).await?;
    ensure!(
        open_batch(&mut tool, 0).await?.is_none(),
        "a batch although they are off"
    );
    ensure!(open_batch(&mut tool, 60).await?.is_none());
    agent.stop().await?;

    let signer = Signer::default().with_batch_lifetime(Duration::from_secs(30));
    let agent = Running::start_with(TakenFor::Agent, &[(1, true)], signer).await?;
    let mut tool = Running::client(&agent.age).await?;
    if peers_are_pinned()? {
        ensure!(
            open_batch(&mut tool, 60).await? == Some(30),
            "longer than the agent allows"
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
        age == [
            "query",
            UNWRAP_EXTENSION,
            NEW_EXTENSION,
            LIST_EXTENSION,
            BATCH_EXTENSION
        ],
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
