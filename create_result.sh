for file in /home/gaurav/Malicious/*; do
    echo "$file"
    cuckoo submit $file > '/home/gaurav/fifile.txt'
    sleep 300s
    python /home/gaurav/delete.py
    mv /home/gaurav/.cuckoo/storage/analyses/* /media/gaurav/a7140a67-7b58-48f7-8c59-9b0154e5f001/Malware_dump
done
