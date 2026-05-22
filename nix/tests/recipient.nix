# Tests for `../recipient.nix`: validateRecipient, resolvedPubkey, and
# extractRecipient. Extractor scans for `age1...` lines only — SSH
# recipients always arrive via explicit `pubkey =` strings.
{ pkgs, lib }:
let
  testLib = import ./lib.nix { inherit pkgs lib; };
  inherit (testLib)
    eq
    recipient
    sampleRecipients
    throws
    ;

  validateAccepts =
    label: value: eq "validate: ${label} passes" (recipient.validateRecipient label value) value;
  validateRejects =
    label: value: throws "validate: ${label} throws" (recipient.validateRecipient label value);

  extractFrom = contents: recipient.extractRecipient (builtins.toFile "id.pub" contents);
  extractEq =
    label: contents: expected:
    eq "extract: ${label}" (extractFrom contents) expected;
  extractThrows = label: contents: throws "extract: ${label}" (extractFrom contents);

  validateTests = [
    (validateAccepts "X25519" sampleRecipients.x25519)
    (validateAccepts "fido2-hmac (dash in HRP)" sampleRecipients.fido2)
    (validateAccepts "ssh-ed25519" sampleRecipients.sshEd25519)
    (validateAccepts "ssh-rsa" sampleRecipients.sshRsa)
    (validateRejects "garbage" "totally-bogus")
    (validateRejects "empty string" "")
  ];

  resolvedTests = [
    (eq "resolvedPubkey: explicit value pass-through" (recipient.resolvedPubkey {
      identity = "/k/dummy";
      pubkey = sampleRecipients.x25519;
    }) sampleRecipients.x25519)
  ];

  extractTests = [
    (extractEq "`# public key:` line" ''
      # public key: ${sampleRecipients.fido2}
      AGE-PLUGIN-FIDO2-HMAC-1QQPbody
    '' sampleRecipients.fido2)
    (extractEq "indented `#    Recipient:` line (yubikey shape)" ''
      #       Serial: 12345678, Slot: 1
      #    Recipient: ${sampleRecipients.x25519}
      AGE-PLUGIN-YUBIKEY-body
    '' sampleRecipients.x25519)
    (extractThrows "no recipient line" "AGE-PLUGIN-FIDO2-HMAC-1QQPbody-without-comment\n")
    (extractThrows "multiple recipient lines" ''
      # public key: ${sampleRecipients.x25519}
      #    Recipient: ${sampleRecipients.fido2}
      AGE-PLUGIN-1QQP
    '')
    (extractThrows "malformed extracted pubkey" ''
      # public key: garbage-not-an-age-recipient
    '')
  ];
in
validateTests ++ resolvedTests ++ extractTests
