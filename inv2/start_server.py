import ssl

import uvicorn

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.SSLv3
ctx.maximum_version = ssl.TLSVersion.TLSv1_3


uvicorn.run("app:app", ssl_keyfile="key.pem"
            , ssl_certfile="cert.pem"
            , ssl_keyfile_password="aaaa", port=4779, host="0.0.0.0")