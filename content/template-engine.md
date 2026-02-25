---
title: Template Engine
description: Penjelasan mengenai arsitektur Template Engine pada lingkup web
tags:
  - web
  - concept
draft: false
---

## Deskripsi
**Template Engine** (Mesin Templat) mengacu kepada sebuah utilitas pemrosesan atau _library_ di level kerangka kerja backend web yang dikonstruksikan sebagai penengah untuk memisahkan struktur presentasi antarmuka HTML dengan elemen fungsio pemrograman yang rumit di belakangnya.

Variasikan tag komputasi khusus (*template variables*) dengan berkas struktur statik, _Template engine_ semacam Jinja2 (Python), Twig (PHP), Pug (Node.js), dan *eval* fungsi terintegrasi, akan mengevaluasi serta membalik skrip bahasa yang dieksekusi menjadi teks akhir/kode *markup* yang dapat dimengerti pangkalan relasi *frontend* dari *client/browser*.

## Risiko Keamanan
Walaupun memudahkan para perancang perangkat lunak membangun laman secara efisien, keledoran desain yang menyertakan masukan pihak tak-tepercaya secara langsung kepada fungsi utilitas translasi teks tingkat _engine_—tanpa dilindungi _context-aware escape filter_—bisa memberikan wewenang kendali server instan (*Server-Side Template Injection* (SSTI) hingga [[remote-code-execution]]).
