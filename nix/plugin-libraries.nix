# What the two age plugins link. The regular one asks the agent and has to
# stay free of libfido2. The standalone one goes into initrds: libfido2 and
# the C runtime, nothing else.
{
  runCommand,
  patchelf,
  # The binaries.
  plugin,
  standalone,
}:
runCommand "plugin-libraries" { nativeBuildInputs = [ patchelf ]; } ''
  runtime='^(libc|libm|libgcc_s|ld-linux[-_a-z0-9]*)\.so\.[0-9]+$'

  needed=$(patchelf --print-needed ${plugin})
  echo "the regular plugin links:" $needed
  more=$(grep -Ev "$runtime" <<<"$needed" || true)
  if [[ -n $more ]]; then
    echo "the regular plugin links more than the C runtime: $more" >&2
    exit 1
  fi

  needed=$(patchelf --print-needed ${standalone})
  echo "the standalone plugin links:" $needed
  if ! grep -Eq '^libfido2\.so\.[0-9]+$' <<<"$needed"; then
    echo "the standalone plugin doesn't link libfido2: is it the right binary?" >&2
    exit 1
  fi
  more=$(grep -Ev "$runtime|^libfido2\.so\.[0-9]+$" <<<"$needed" || true)
  if [[ -n $more ]]; then
    echo "the standalone plugin links more than libfido2 and the C runtime: $more" >&2
    exit 1
  fi
  touch $out
''
