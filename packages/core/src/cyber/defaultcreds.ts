export type DefaultCred = {
  product: string
  service: string
  username: string
  password: string
}

export const DEFAULT_CREDS: DefaultCred[] = [
  { product: "Apache Tomcat", service: "tomcat", username: "tomcat", password: "tomcat" },
  { product: "Apache Tomcat manager", service: "tomcat", username: "admin", password: "admin" },
  { product: "Jenkins", service: "jenkins", username: "admin", password: "admin" },
  { product: "Grafana", service: "grafana", username: "admin", password: "admin" },
  { product: "Kibana", service: "kibana", username: "elastic", password: "changeme" },
  { product: "Elasticsearch", service: "elasticsearch", username: "elastic", password: "changeme" },
  { product: "JBoss", service: "jboss", username: "admin", password: "admin" },
  { product: "WebLogic", service: "weblogic", username: "weblogic", password: "welcome1" },
  { product: "WebSphere", service: "websphere", username: "wsadmin", password: "password" },
  { product: "GlassFish", service: "glassfish", username: "admin", password: "adminadmin" },
  { product: "WildFly", service: "wildfly", username: "admin", password: "admin" },
  { product: "phpMyAdmin", service: "mysql-web", username: "root", password: "" },
  { product: "MySQL", service: "mysql", username: "root", password: "" },
  { product: "PostgreSQL", service: "postgres", username: "postgres", password: "postgres" },
  { product: "MongoDB", service: "mongodb", username: "admin", password: "admin" },
  { product: "Redis (no auth)", service: "redis", username: "", password: "" },
  { product: "Mongo Express", service: "mongo-express", username: "admin", password: "pass" },
  { product: "RabbitMQ management", service: "rabbitmq", username: "guest", password: "guest" },
  { product: "ActiveMQ", service: "activemq", username: "admin", password: "admin" },
  { product: "Nginx Amplify", service: "nginx", username: "admin", password: "admin" },
  { product: "WordPress", service: "wordpress", username: "admin", password: "admin" },
  { product: "Drupal", service: "drupal", username: "admin", password: "admin" },
  { product: "Joomla", service: "joomla", username: "admin", password: "admin" },
  { product: "Moodle", service: "moodle", username: "admin", password: "admin" },
  { product: "pfSense", service: "pfsense", username: "admin", password: "pfsense" },
  { product: "F5 BIG-IP", service: "big-ip", username: "admin", password: "admin" },
  { product: "Cisco ASA", service: "cisco", username: "cisco", password: "cisco" },
  { product: "VMware ESXi", service: "esxi", username: "root", password: "" },
  { product: "vCenter", service: "vcenter", username: "administrator@vsphere.local", password: "" },
  { product: "Docker Registry (no auth)", service: "registry", username: "", password: "" },
  { product: "SonarQube", service: "sonarqube", username: "admin", password: "admin" },
  { product: "Zabbix", service: "zabbix", username: "Admin", password: "zabbix" },
  { product: "Nagios XI", service: "nagios", username: "nagiosadmin", password: "nagiosadmin" },
  { product: "Splunk", service: "splunk", username: "admin", password: "changeme" },
]

export function lookupDefaultCreds(query: string): DefaultCred[] {
  const needle = query.trim().toLowerCase()
  if (!needle) return []
  return DEFAULT_CREDS.filter(
    (cred) => cred.product.toLowerCase().includes(needle) || cred.service.includes(needle),
  )
}
