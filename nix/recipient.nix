# Pure age-recipient helpers.
{ lib }:
let
  inherit (lib) splitString;
  inherit (builtins)
    concatStringsSep
    elemAt
    filter
    head
    isString
    length
    match
    readFile
    toJSON
    ;

  # Keywords that introduce a recipient line in identity files.
  recipientKeywords = [
    "public key"
    "Recipient"
  ];

  keywordAlternation = concatStringsSep "|" recipientKeywords;

  recipientPattern = ".*(${keywordAlternation}): (age1[0-9a-z-]+).*";
in
rec {
  inherit recipientKeywords;

  # Accepts age-native and ssh recipients.
  validateRecipient =
    sourceLabel: value:
    if
      isString value && match "(age1[0-9a-z-]+|(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/=]+.*)" value != null
    then
      value
    else
      throw "tombkey: ${sourceLabel} is not a valid age recipient: ${toJSON value}";

  extractRecipient =
    identityPath:
    let
      content = readFile identityPath;
      lines = splitString "\n" content;
      extractFromLine =
        line:
        let
          matched = match recipientPattern line;
        in
        if matched == null then null else elemAt matched 1;
      recipients = filter (x: x != null) (map extractFromLine lines);
    in
    if recipients == [ ] then
      throw "tombkey: no recipient comment in ${toString identityPath} (expected one of ${toJSON recipientKeywords})"
    else if length recipients > 1 then
      throw "tombkey: ${toString (length recipients)} recipient comments in ${toString identityPath}; set `pubkey =` explicitly to disambiguate"
    else
      validateRecipient "extracted from ${toString identityPath}" (head recipients);

  resolvedPubkey =
    entry:
    if entry.pubkey != null then
      validateRecipient "masterIdentities[...].pubkey for ${toString entry.identity}" entry.pubkey
    else
      extractRecipient entry.identity;
}
