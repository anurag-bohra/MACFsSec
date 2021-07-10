import yaml
import sqlite3
from elasticsearch import Elasticsearch
import requests
import os
from macholib import MachO
import subprocess
import hashlib
import json


def read_yaml():
    with open('settings.yaml', 'r') as rFile:
        yaml_file = yaml.load(rFile, Loader=yaml.FullLoader)
    return yaml_file


def form_regex():
    settings = read_yaml()
    extensions = settings['extensions']
    extension_regex = '|'.join(extensions)
    extension_regex = '.*\\.(' + extension_regex + ')$'
    return extension_regex


def check_macho(file_path):
    flag = False
    if os.path.exists(file_path):
        try:
            filetype = MachO.MachO(file_path).headers
            flag = True
        except Exception:
            flag = False
        finally:
            return flag


def check_signature(file_path):
    if os.path.exists(file_path):
        command = ['codesign', '-v', file_path]
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout = (proc.stdout).decode('utf-8')
        stderr = (proc.stderr).decode('utf-8')
        retcode = proc.returncode
        redFlag = False
        isSigned = False
        if retcode == 0 and stderr == "" and stdout == "":
            isSigned = True
        if retcode != 0 and "CSSMERR_TP_CERT_REVOKED" in stderr:
            redFlag = True
        return isSigned, redFlag
    return None, None


def create_clients_table(conn):
    create_table_query = """
                CREATE TABLE FILES
                (PATH TEXT NOT NULL,
                HASH TEXT NOT NULL,
                VT_SCORE TEXT DEFAULT "UNKNOWN",
                IS_SIGNED TEXT DEFAULT "UNKNOWN",
                CERT_REVOKED TEXT DEFAULT "UNKNOWN"
                );
            """
    conn.execute(create_table_query)
    conn.commit()


def database_init(dbfile):
    conn = sqlite3.connect(dbfile)
    DBCursor = conn.cursor()
    DBCursor.execute(''' SELECT name FROM sqlite_master WHERE type='table' AND name='FILES' ''')
    if not DBCursor.fetchall():
        create_clients_table(conn)
    return conn, DBCursor


def check_file_exists_db(file_path, sha256, cursor):
    flag = False
    check_query = """
        SELECT HASH FROM FILES WHERE HASH='{hash}' AND PATH='{path}';
    """.format(hash=sha256, path=file_path)
    cursor.execute(check_query)
    data = cursor.fetchall()
    if not len(data) == 0:
        flag = True
    return False


def parse_vt_data(data):
    if "error" in data.keys():
        return "UNKNOWN"
    elif "data" in data.keys():
        parse1 = data['data']['attributes']
        if 'last_analysis_stats' in parse1.keys():
            last_analysis_stats = parse1['last_analysis_stats']
            score_string = str(last_analysis_stats['malicious']) + '/' + str(last_analysis_stats['malicious'] + last_analysis_stats['undetected'])
            return score_string
    else:
        return "UNKNOWN"


def get_vt_score(api_key, sha256):
    file_url = 'https://www.virustotal.com/api/v3/files/' + str(sha256)
    headers = {'x-apikey': api_key}
    resp = requests.get(file_url, headers=headers)
    data = json.loads(resp.text)
    score = parse_vt_data(data)
    return score


def insert_row_database(DBfile, payload):
    conn, cursor = database_init(DBfile)
    insert_query = """
        INSERT INTO FILES VALUES('{path}', '{hash}', '{VTscore}', '{isSigned}', '{isRevoked}');    
    """.format(path=payload['filePath'], hash=payload['Sha256'], VTscore=payload['VirusTotal Score'], isSigned=payload['isSigned'], isRevoked=payload['Cert Revoked'])
    conn.execute(insert_query)
    conn.commit()
    conn.close()


def get_vt_score_from_db(file_hash, DBfile):
    conn, cursor = database_init(DBfile)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    query = """SELECT * FROM FILES WHERE HASH='{hash}'""".format(hash=file_hash)
    cursor.execute(query)
    rows_data = cursor.fetchall()
    result = [dict(row) for row in rows_data]
    conn.close()
    for row in result:
        return row['VT_SCORE']
    return "UNKNOWN"


def check_database_and_insert(payload, settings):
    DBfile = settings['databaseFile']
    conn, cursor = database_init(DBfile)
    existFlag = check_file_exists_db(payload['filePath'], payload['Sha256'], cursor)
    conn.close()
    if not existFlag:
        if settings['enableVT']:
            payload['VirusTotal Score'] = get_vt_score(settings['virustotalAPI'], payload['Sha256'])
            insert_row_database(DBfile, payload)
        else:
            insert_row_database(DBfile, payload)
    else:
        payload['VirusTotal Score'] = get_vt_score_from_db(payload['Sha256'], payload['filePath'])
    return payload


def get_sha256_hash(file_path):
    if os.path.exists(file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as rFile:
            for byte_block in iter(lambda: rFile.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    else:
        return ""


def send_data_to_elastic(settings, payload):
    host = settings['elasticIP']
    port = int(settings['elasticPort'])
    es = Elasticsearch(host, port=port)
    es.index(index='MACfsSec', body=payload)


def event_handler(event):
    payload = dict()
    payload['filePath'] = event.src_path
    payload['eventType'] = event.event_type
    payload['isSigned'] = None
    payload['Cert Revoked'] = None
    payload['Sha256'] = get_sha256_hash(event.src_path)
    payload['VirusTotal Score'] = ""
    is_signed, cert_revoked = check_signature(event.src_path)
    payload['isSigned'] = is_signed
    payload['Cert Revoked'] = cert_revoked
    settings = read_yaml()
    payload = check_database_and_insert(payload, settings)
    if settings['enableElastic']:
        send_data_to_elastic(settings, payload)
