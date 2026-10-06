# Ontology

The extractor is held to `crawler/config/ontology.json` (version `2026-10-04`). The LLM is constrained at the API level by a JSON schema generated from this file, and the validator drops anything outside it, so the extractor cannot invent types or relations.

## Entity types (15)

| Name | Label | Description |
|---|---|---|
| `ThreatActor` | Threat actor | An individual attacker, persona or unnamed actor (e.g. 'a Russian-speaking hacker', 'the operator'). Named APT groups are ThreatGroup. |
| `ThreatGroup` | Threat group | A named hacking group, APT or crime gang (APT28, Lazarus Group, FIN7, OilRig). |
| `Malware` | Malware | Malicious software: backdoors, RATs, trojans, ransomware, loaders (X-Agent, PlugX, WannaCry, Emotet). |
| `AttackTechnique` | Attack technique | A specific adversary technique, usually a MITRE ATT&CK technique or ID (Spearphishing Attachment, T1566.001, credential dumping). |
| `Vulnerability` | Vulnerability | A software weakness or exploit, including CVE IDs (CVE-2017-11882, a zero-day in Flash, EternalBlue). |
| `Software` | Software | Legitimate software or a product that is attacked, abused or vulnerable (Microsoft Office, Windows, Adobe Flash). |
| `Tool` | Tool | Dual-use or offensive tooling that is not malware itself (Mimikatz, PsExec, Impacket, PowerShell). |
| `Organization` | Organization | A targeted or involved company, agency or sector (banks, government agencies, Microsoft, the energy sector). |
| `AttackPattern` | Attack pattern | A general method or style of attack not tied to one technique (phishing, watering hole attacks, supply-chain attack, brute force). |
| `FileHash` | File/hash | A file name, file sample or hash (MD5/SHA1/SHA256) (invoice.doc, svchost.exe, d41d8cd98f00b204e9800998ecf8427e). |
| `NetworkInfra` | Network infrastructure | An IP address, domain, URL or server used in attacks, including defanged forms (185.12.45[.]6, evil[.]com, C2 server). |
| `Asset` | Asset/system | A victim system, device or network (email servers, ICS systems, endpoints, domain controllers). |
| `SecurityTeam` | Security team | A security vendor, research team or CERT (FireEye, Kaspersky Lab, Unit 42, US-CERT). |
| `Time` | Time | A date, year, month or period (2017, March 2019, late 2018). |
| `Location` | Location | A country, region, city or nationality (Russia, the Middle East, Ukrainian). |

## Relations (26)

Each relation is stored once, in one direction, with an inverse name for the other direction. Relations with a generic target apply from any entity type and are used only when no more specific relation fits.

| Relation | Inverse | Meaning | Allowed source → target |
|---|---|---|---|
| `alias-of` | `alias-of` | two names for the same actor or group | ThreatActor → ThreatActor, ThreatActor → ThreatGroup, ThreatGroup → ThreatActor, ThreatGroup → ThreatGroup |
| `uses` | `used-by` | an actor, group or technique uses malware, a tool, software, a technique or a pattern | ThreatActor → Malware, ThreatActor → AttackTechnique, ThreatActor → Tool, ThreatActor → AttackPattern, ThreatActor → Software, ThreatGroup → Malware, ThreatGroup → AttackTechnique, ThreatGroup → Tool, ThreatGroup → AttackPattern, ThreatGroup → Software, AttackTechnique → Tool, AttackTechnique → Malware |
| `targets` | `targeted-by` | an actor, group or technique targets an organization, asset or vulnerability | ThreatActor → Organization, ThreatActor → Asset, ThreatGroup → Organization, ThreatGroup → Asset, AttackTechnique → Vulnerability, AttackTechnique → Asset |
| `operates-in` | `operation-area-of` | an actor or group is active in a location | ThreatActor → Location, ThreatGroup → Location |
| `originated-from` | `origin-of` | an actor or group comes from a location | ThreatActor → Location, ThreatGroup → Location |
| `active-at` | `activity-time-of` | an actor or group is active at a time | ThreatActor → Time, ThreatGroup → Time |
| `variant-of` | `has-variant` | malware or a tool is a variant of malware or a tool; a technique or pattern is a variant of a technique or pattern | Malware → Malware, Malware → Tool, Tool → Malware, Tool → Tool, AttackTechnique → AttackTechnique, AttackTechnique → AttackPattern, AttackPattern → AttackTechnique, AttackPattern → AttackPattern |
| `sub_technique_of` | `has_sub_technique` | a technique or pattern is a sub-technique of a technique or pattern | AttackTechnique → AttackTechnique, AttackTechnique → AttackPattern, AttackPattern → AttackTechnique, AttackPattern → AttackPattern |
| `drops` | `dropped-by` | malware drops a file | Malware → FileHash |
| `exploits` | `exploited-by` | malware or a tool exploits a vulnerability | Malware → Vulnerability, Tool → Vulnerability |
| `affects` | `affected-by` | malware or a vulnerability affects software or an asset | Malware → Software, Malware → Asset, Vulnerability → Software, Vulnerability → Asset |
| `communicates-with` | `contacted-by` | malware or a tool communicates with network infrastructure | Malware → NetworkInfra, Tool → NetworkInfra |
| `contains` | `contained-in` | software contains a vulnerability | Software → Vulnerability |
| `runs-on` | `hosts` | software runs on an asset/system | Software → Asset |
| `mitigates` | `mitigated-by` | a security team mitigates a technique or a vulnerability | SecurityTeam → AttackTechnique, SecurityTeam → Vulnerability |
| `remediated-by` | `remediates` | a vulnerability is remediated by software (a patch or update) | Vulnerability → Software |
| `belongs-to` | `owns` | an asset or network infrastructure belongs to an organization | Asset → Organization, NetworkInfra → Organization |
| `located-in` | `location-of` | something is located in a location (any entity: only when no more specific relation to a location fits) | Asset → Location, NetworkInfra → Location; *any type* → Location |
| `monitored-by` | `monitors` | an asset/system is monitored by a security team | Asset → SecurityTeam |
| `indicates` | `indicated-by` | a file/hash indicates malware or a threat actor | FileHash → Malware, FileHash → ThreatActor |
| `downloads-from` | `download-source-of` | a file downloads from network infrastructure | FileHash → NetworkInfra |
| `utilized-by` | `utilizes` | network infrastructure is utilized by an actor, group or malware | NetworkInfra → ThreatActor, NetworkInfra → ThreatGroup, NetworkInfra → Malware |
| `investigates` | `investigated-by` | a security team investigates an actor or group | SecurityTeam → ThreatActor, SecurityTeam → ThreatGroup |
| `detects` | `detected-by` | a security team detects malware, a vulnerability or an attack pattern | SecurityTeam → Malware, SecurityTeam → Vulnerability, SecurityTeam → AttackPattern |
| `patches` | `patched-by` | a security team patches an asset/system | SecurityTeam → Asset |
| `occurs-at` | `time-of` | something happens at a time (any entity: only when no more specific relation to a time fits) | *any type* → Time |

## Changing the ontology

1. Edit `crawler/config/ontology.json` (add entity types or relation pairs; bump `version`).
2. The file is validated on load; an inconsistent entry (e.g. a pair naming an unknown type) stops the command with the problem named.
3. Output files record the `ontology_version` they were produced with. Re-run `crawler extract --force` to regenerate older output.
4. Rule-based detection (`extraction/patterns.py`, `resources/entities.json`) only finds types it has patterns/dictionaries for; new types are found by the LLM only. Add examples to `extraction/resources/examples.json` if the LLM needs guidance.

Background: the type and relation set derives from `legacy/text-extractor/Entities_and_relations_1.pdf`; see `docs/CTI_INTEGRATION.md` for the exact brief.
