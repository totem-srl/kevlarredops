export type TakeoverFingerprint = {
  service: string
  cnamePattern: RegExp
  vulnerable: boolean
  detail: string
}

export const TAKEOVER_FINGERPRINTS: TakeoverFingerprint[] = [
  { service: "AWS S3", cnamePattern: /\.s3\.amazonaws\.com$|\.s3-[a-z0-9-]+\.amazonaws\.com$/, vulnerable: true, detail: "S3 bucket names are globally unique; an unclaimed bucket referenced by CNAME can be registered by anyone." },
  { service: "GitHub Pages", cnamePattern: /^([a-z0-9-]+\.)*github\.io$/, vulnerable: true, detail: "Custom domains pointing at github.io can be claimed via a repo with a matching CNAME file." },
  { service: "Heroku", cnamePattern: /^[a-z0-9-]+\.herokuapp\.com$/, vulnerable: true, detail: "herokuapp subdomains are recyclable once the original app is deleted." },
  { service: "Azure Web Apps", cnamePattern: /^[a-z0-9-]+\.azurewebsites\.net$/, vulnerable: true, detail: "Deleted Azure Web App slots leave the custom domain claimable." },
  { service: "Azure CDN", cnamePattern: /^[a-z0-9-]+\.azureedge\.net$|^[a-z0-9-]+\.afd\.azureedge\.net$/, vulnerable: true, detail: "Azure CDN endpoints can be re-registered after deletion." },
  { service: "CloudFront", cnamePattern: /^[a-z0-9]+\.cloudfront\.net$/, vulnerable: true, detail: "Dangling CloudFront distributions referenced by CNAME may be recreated by another account." },
  { service: "Fastly", cnamePattern: /^[a-z0-9-]+\.fastly\.net$|^[a-z0-9-]+\.freetls\.fastly\.net$/, vulnerable: true, detail: "Fastly domains become claimable when the backing service is removed." },
  { service: "Netlify", cnamePattern: /^[a-z0-9-]+\.netlify\.app$|^[a-z0-9-]+\.netlify\.global\.ssl\.fastly\.net$/, vulnerable: true, detail: "Netlify subdomains can be re-registered after the site is deleted." },
  { service: "GitLab Pages", cnamePattern: /^[a-z0-9-]+\.gitlab\.io$/, vulnerable: true, detail: "GitLab Pages projects removed without domain release allow re-registration." },
  { service: "WordPress.com", cnamePattern: /^[a-z0-9-]+\.wordpress\.com$|^[a-z0-9-]+\.files\.wordpress\.com$/, vulnerable: true, detail: "WordPress.com blog aliases can be claimed after deletion." },
  { service: "Pantheon", cnamePattern: /^[a-z0-9-]+\.pantheonsite\.io$/, vulnerable: true, detail: "Pantheon site environments are recyclable." },
  { service: "Zendesk", cnamePattern: /^[a-z0-9-]+\.zendesk\.com$/, vulnerable: true, detail: "Zendesk support subdomains can be re-registered on trial plans." },
  { service: "Helpjuice", cnamePattern: /^[a-z0-9-]+\.helpjuice\.com$/, vulnerable: true, detail: "Helpjuice knowledge-base subdomains are claimable after account removal." },
  { service: "Shopify", cnamePattern: /^[a-z0-9-]+\.myshopify\.com$/, vulnerable: false, detail: "Shopify mitigated takeover for myshopify subdomains; still worth verifying manually." },
]

const BODY_MARKERS: { pattern: RegExp; service: string; detail: string }[] = [
  { pattern: /There isn'?t a GitHub Pages site here/i, service: "GitHub Pages", detail: "404 body indicates unclaimed GitHub Pages site" },
  { pattern: /NoSuchBucket/i, service: "AWS S3", detail: "NoSuchBucket error indicates dangling S3 reference" },
  { pattern: /The specified bucket does not exist/i, service: "AWS S3", detail: "S3 missing-bucket message" },
  { pattern: /404 Not Found.*nginx.*Heroku|No such app/i, service: "Heroku", detail: "Heroku no-such-app response" },
  { pattern: /404 Web Site not found/i, service: "Azure Web Apps", detail: "Azure App Service default 404" },
  { pattern: /Fastly error: unknown domain/i, service: "Fastly", detail: "Fastly unknown-domain error" },
]

export function matchTakeover(input: { cname?: string; body?: string }): TakeoverFingerprint | null {
  if (input.cname) {
    const host = input.cname.toLowerCase().replace(/\.$/, "")
    for (const fingerprint of TAKEOVER_FINGERPRINTS) {
      if (fingerprint.cnamePattern.test(host)) return fingerprint
    }
  }
  if (input.body) {
    for (const marker of BODY_MARKERS) {
      if (marker.pattern.test(input.body)) {
        const fingerprint = TAKEOVER_FINGERPRINTS.find((f) => f.service === marker.service)
        if (fingerprint) return fingerprint
      }
    }
  }
  return null
}
