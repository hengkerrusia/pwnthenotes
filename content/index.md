---
title: Pwn The Notes
description: Web Security Vulnerability Knowledge Library — Mutation Taxonomy & Attack Surface Reference
---

## What is this?
**Pwn The Notes** is a web security vulnerability knowledge library that systematically classifies over 100 web vulnerability classes into 13 categories. Unlike conventional cheat sheets or CVE lists, each topic is organized based on structural mutation criteria — what is mutated, what mismatch results, and where it is exploited as an attack.

Each topic is an in-depth structured reference document, covering the entire attack surface of a vulnerability class through a three-axis taxonomy (Mutation Target, Bypass/Mismatch Type, Attack Scenario).

## Topics

### Injection

| Category | Description |
| --- | --- |
| [SQL Injection](injection/sql-injection.md) | SQL injection mutation vectors and filter bypass taxonomy |
| [NoSQL Injection](injection/nosql-injection.md) | NoSQL injection operators, syntax variations, and blind extraction |
| [Command Injection](injection/command-injection.md) | OS command injection chaining, filter evasion, and shell-specific mutations |
| [XSS](injection/xss.md) | Context-dependent Cross-Site Scripting payloads and filter bypasses |
| [SSTI](injection/SSTI.md) | Server-Side Template Injection in various template engines |
| [EL Injection](injection/el-injection.md) | Expression Language injection in Java EE / Spring ecosystem |
| [XXE](injection/xxe.md) | XML External Entity injection, OOB exfiltration, and parser differentials |
| [LDAP / XPath Injection](injection/ldap-xpath.md) | Query injection mutation taxonomy on LDAP and XPath |
| [Prototype Pollution](injection/prototype-pollution.md) | JavaScript prototype chain pollution vectors and gadget chains |
| [GraphQL](injection/graphql.md) | GraphQL introspection abuse, batching attacks, and injection vectors |
| [LaTeX Injection](injection/latex-injection.md) | LaTeX injection mutation vectors and document processing exploitation |
| [Protocol-Level Injection](injection/protocol-level-injection.md) | Protocol-level injection on SMTP, LDAP, and other wire protocols |
| [SSI / ESI / XSLT Injection](injection/ssi-esi-xslt-injection.md) | Server-Side Includes, Edge Side Includes, and XSLT injection for RCE |
| [ORM Misuse → SQL Injection](injection/orm-misue-sql-injection.md) | ORM query function misuse leading to SQL injection |
| [CSV Formula Injection](injection/csv-formula-injection.md) | Spreadsheet formula injection through CSV/Excel export functionality |
| [CSS Injection](injection/css-injection.md) | CSS-based data exfiltration and style injection attacks |

## Authentication & Authorization
| Category | Description |
| --- | --- |
| [Authentication Bypass & SSO](auth/authentication-sso-bypass.md) | Authentication bypass patterns and Single Sign-On mechanisms. |
| [OAuth](auth/oauth.md) | OAuth 2.0 flow exploitation and token theft patterns. |
| [JWT](auth/jwt.md) | JSON Web Token algorithm confusion, key injection, and claim abuse. |
| [SAML](auth/saml.md) | SAML assertion forgery, signature wrapping, and parser differentials. |
| [CORS Misconfiguration](auth/cors.md) | Cross-Origin Resource Sharing misconfiguration exploitation patterns. |
| [IDOR / BOLA](auth/idor.md) | Broken Object Level Authorization and reference manipulation. |
| [Account Takeover](auth/ATO.md) | Authentication bypass chains and account recovery exploitation. |
| [Mass Assignment](auth/mass-assigment.md) | Parameter binding abuse and hidden field injection. |
| [Cryptographic Implementation Vulnerabilities](auth/cryto.md) | Cryptographic implementation vulnerabilities in web contexts and bypass patterns. |
