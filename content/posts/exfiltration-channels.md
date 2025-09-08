+++
date = '2025-09-01T23:42:33+05:00'
draft = true
title = 'Anatomy of Exfiltration 📤'
author = 's0ld13r'
tags = ['data exfiltration', 'threat hunting', 'data security']
+++

## Intro

Exfiltration consists of techniques that adversaries may use to steal data from your network. Once they’ve collected data, adversaries often package it to avoid detection while removing it. This can include compression and encryption. Techniques for getting data out of a target network typically include transferring it over their command and control channel or an alternate channel and may also include putting size limits on the transmission.

## Disclaimer
This article is intended strictly for educational and research purposes. The techniques, tools, and concepts discussed here are designed to enhance understanding of adversary tactics, improve defensive capabilities, and support authorized Red Team assessments. Any unauthorized or malicious use of the information provided is strongly condemned and may be illegal.

## Widely Used Exfiltration Tools

- Cloud services (Google Drive, OneDrive, Mega.nz)
- FTP - FileZilla
- SSH - PuTTY, WinSCP, scp.exe
- RDP 
- SMTP
- AnyDesk, TeamViewer

## Advanced Exfiltration Tooling


## Detection & Mitigation


