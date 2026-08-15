// App configuration - defines available audits and branding
export interface AuditConfig {
  id: string;
  name: string;
  description: string;
  icon: string;
  category: 'network' | 'security' | 'infrastructure';
}

export interface AppConfig {
  app_name: string;
  version: string;
  audits: AuditConfig[];
}

export function getAppConfig(): AppConfig {
  return {
    app_name: 'Ency Audit Toolkit',
    version: '0.1.0',
    audits: [
      {
        id: 'firewall',
        name: 'Firewall Configuration Audit',
        description:
          'Analyze firewall configs (PfSense, OPNsense, iptables, pf) for overly permissive rules, weak protocols, and management exposure.',
        icon: '🛡️',
        category: 'network',
      },
      {
        id: 'dns',
        name: 'DNS Security Audit',
        description:
          'Check SPF, DKIM, DMARC, and DNSSEC records for your domain. Catch misconfigurations that enable email spoofing.',
        icon: '🌐',
        category: 'security',
      },
      {
        id: 'ssl',
        name: 'SSL/TLS Certificate Audit',
        description:
          'Verify certificate validity, encryption strength, and protocol support. Detect weak ciphers and expired certs.',
        icon: '🔒',
        category: 'security',
      },
    ],
  };
}
