
master="192.168.2.27"
master_port="10000"

cd developer;
rm -f pythonfunc.zip;
7z a -tzip pythonfunc.zip *;
HOST=$(curl --data-binary @pythonfunc.zip $master:$master_port/function | awk '{ print $3 }');
curl --resolve $HOST:$master_port:$master http://$HOST:$master_port/init
cd ..;

echo functionid: $HOST;

echo starting 100 clients

for i in {1..100}; do
    python3 client/client.py $HOST $master $master_port &
done

wait < <(jobs -p);

ROUND=$(curl --resolve $HOST:$master_port:$master http://$HOST:$master_port/getRound);
model=$(curl --resolve $HOST:$master_port:$master http://$HOST:$master_port/getModel);
echo Total round $ROUND
echo model $model
#curl --resolve $HOST:$master_port:$master \
#     -H 'data: { "round": 1, "model": [[1.0, 1.1, 1.2], [1.0, 1.1, 1.2]] }' \
#     http://$HOST:$master_port/clientUpload;
