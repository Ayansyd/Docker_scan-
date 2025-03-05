
        rule suspicious_strings {
            meta:
                description = "Detect suspicious strings in container files"
                author = "Security Team"
                severity = "high"
            strings:
                $shell1 = "nc -e /bin/sh" nocase
                $shell2 = "bash -i >& /dev/tcp/" nocase
                $shell3 = "/bin/sh -i" nocase
                $miner1 = "xmrig" nocase
                $miner2 = "cpuminer" nocase
                $ssh_key = "ssh-rsa " 
            condition:
                any of them
        }
        