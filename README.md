# Check ARI status for a certificate

This implements [draft-ietf-acme-ari-05](https://datatracker.ietf.org/doc/draft-ietf-acme-ari/05/)

## Installation

```
go install github.com/jcjones/ari-fetch@latest
```

## Usage

ari-fetch assumes you're using Let's Encrypt's production API. To change that, use the `-acme` flag.

```sh
2024/09/27 19:56:28 INFO ARI Request InputPEM=example.pem renewalInfoURL=https://acme-v02.api.letsencrypt.org/draft-ietf-acme-ari-03/renewalInfo/xc9GpOr0w8B6bJXELbBeki8m47k.A4Pd62UjVrFJIb2C6eUk67_n
{
    "ExplanationURL": "",
    "SuggestedWindow": {
        "Start": "2024-11-25T20:04:18Z",
        "End": "2024-11-27T20:04:18Z"
    }
}
```

You can get extra details with the `-v` flag:

```sh
○ → ari-fetch -v revoked.pem
2024/09/27 19:55:42 DEBUG HTTP ACME Directory GET completed URL=https://acme-v02.api.letsencrypt.org/directory "response status"=200 dict={RenewalInfo:https://acme-v02.api.letsencrypt.org/draft-ietf-acme-ari-03/renewalInfo}
2024/09/27 19:55:42 DEBUG Authority Key Identifier hex=9327469803a951688e98d6c44248db23bf5894d2 base64=kydGmAOpUWiOmNbEQkjbI79YlNI
2024/09/27 19:55:42 DEBUG AKI string extension found base64=kydGmAOpUWiOmNbEQkjbI79YlNI
2024/09/27 19:55:42 DEBUG Serial Number hex=03515bec651a7d0084f9517fc2da98d2fdb9 base64=A1Fb7GUafQCE-VF_wtqY0v25
2024/09/27 19:55:42 INFO ARI Request InputPEM=revoked.pem renewalInfoURL=https://acme-v02.api.letsencrypt.org/draft-ietf-acme-ari-03/renewalInfo/kydGmAOpUWiOmNbEQkjbI79YlNI.A1Fb7GUafQCE-VF_wtqY0v25
{
    "ExplanationURL": "",
    "SuggestedWindow": {
        "Start": "2024-09-28T01:55:42.412341986Z",
        "End": "2024-09-28T02:25:42.412341986Z"
    }
}
```

You can also call it on multiple certificates at time.
