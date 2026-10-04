# CTI Crawler & Extractor Integration Plan

## Role & Context
You are a Senior Python Engineer merging two separate codebases—a headless CTI web crawler and an LLM-based entity/relation extractor—into a unified, automated data pipeline. Your goal is to decouple the extractor from its web UI, integrate it into the crawler's CLI, enforce a strict CTI ontology, and externalize configuration.

## Objective 1: Dynamic Source Configuration
The crawler currently hardcodes sources in `sources/news_rss.py`, `sources/sitemap.py`, and `sources/wordpress.py`. 
1. Create a `config/sources.yaml` file to store all crawler targets.
2. Refactor the source registration logic so the crawler dynamically loads adapters (RSS, Sitemap, WordPress, etc.) based on this YAML file. 
3. Ensure the schema supports fields like `name`, `adapter`, `entry_url`, `rate_limit`, `license`, and adapter-specific flags (e.g., `child_pattern` for sitemaps).

## Objective 2: Strict Ontology Configuration
The extractor must NEVER hallucinate or predict unapproved entities or relations. 
1. Create a `config/ontology.json` file defining exactly 15 entities and their valid relation triples.
2. The exact entities to define are: 
   Threat actor, Threat group, Malware, Attack technique, Vulnerability, Software, Tool, Organization, Attack pattern, File/hash, Network infrastructure, Asset/system, Security team, Time, Location.
3. Define the valid mapped relations exactly as follows:
   - Threat Actor/Group -> alias-of -> Threat Actor/Group
   - Threat Actor/Group -> uses -> Malware, Attack technique, Tool, Attack pattern, Software
   - Threat Actor/Group -> targets -> Organization, Asset/system
   - Threat Actor/Group -> operates-in, originated-from -> Location
   - Threat Actor/Group -> active-at -> Time
   - Malware/Tool -> variant-of -> Malware/Tool
   - Malware -> drops -> File/hash
   - Malware/Tool -> exploits -> Vulnerability
   - Malware -> affects -> Software, Asset/system
   - Malware/Tool -> communicates-with -> Network infrastructure
   - Software -> contains -> Vulnerability
   - Software -> runs-on -> Asset/system
   - Attack technique/pattern -> sub_technique_of / variant-of -> Attack technique/pattern
   - Attack technique -> uses -> Tool, Malware
   - Attack technique -> targets -> Vulnerability, Asset/system
   - Attack technique -> mitigated-by -> Security team
   - Vulnerability -> affects -> Software, Asset/system
   - Vulnerability -> remediated-by -> Software
   - Asset/system -> belongs-to -> Organization
   - Asset/system -> located-in -> Location
   - Asset/system -> monitored-by -> Security team
   - File/hash -> indicates -> Malware, Threat actor
   - File/hash -> downloads-from -> Network infrastructure
   - Network infrastructure -> belongs-to -> Organization
   - Network infrastructure -> located-in -> Location
   - Network infrastructure -> utilized-by -> Threat actor, Threat group, Malware
   - Security team -> investigates -> Threat actor, Threat group
   - Security team -> detects -> Malware, Vulnerability, Attack pattern
   - Security team -> mitigates -> Vulnerability
   - Security team -> patches -> Asset/system
   - Any Entity -> occurs-at -> Time
   - Any Entity -> located-in -> Location

## Objective 3: Headless Extraction Pipeline
1. Port the core logic from `Extractor-main` (specifically `extractors/`, `formatter.py`, `validator.py`) into a new module in the crawler: `src/crawler/extraction/`.
2. Completely delete or ignore the Flask/FastAPI web app (`app.py`, `static/index.html`).
3. Update the LLM extraction logic (e.g., `extractors/llm.py` or prompts) to dynamically load `config/ontology.json`. 
4. Implement Structured Outputs (JSON Schema API parameters) to strictly constrain the LLM. It must be forced at the API level to return ONLY the entities and relations defined in the JSON configuration.

## Objective 4: CLI Integration & JSON Export
1. Add a new Typer command to `cli.py` (e.g., `crawler extract`).
2. This command should query un-extracted documents from the PostgreSQL `documents` table (or read from the raw archive), process them through the rules/patterns pass, and then the strictly constrained LLM pass.
3. Export the final structured output (entities with offsets, relation triples) to disk as a JSON or JSONL file (e.g., `data/extracted/<url_hash>.json`).

## Execution Constraints
- Do not modify the existing database schema for extraction right now; focus purely on the JSON/JSONL file export.
- Retain the crawler's existing `Fetcher` and concurrency controls to prevent rate limits.
- Write robust, production-ready code with type hints.
- Start by generating the `sources.yaml` and `ontology.json` files, then refactor the Python code to consume them.