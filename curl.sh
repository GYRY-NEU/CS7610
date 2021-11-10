curl -X PUT -H "Content-Type: application/json" -d '{"host":"127.0.0.3", "port":8080}' localhost:10000
curl --data-binary @build-debug/bin/run localhost:10000 -v
curl --resolve example.com:10000:127.0.0.1 http://example.com:10000
