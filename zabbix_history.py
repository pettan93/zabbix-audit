#!/usr/bin/env python

import argparse
import logging
import psycopg2
import splunklib.client as client

class ZabbixAudit(object):
    """ Object wrapper to get audit info from zabbix """

    def __init__(self, zabbixdb_conf,zabbixhost_conf, continueFrom):
        self.db = psycopg2.connect(**zabbixdb_conf)
        self.dbc = self.db.cursor()
        self.sp_name = 'get_history'
        if not self._is_sp_exist(self.sp_name):
            self._create_sp(self.sp_name)

    def _is_sp_exist(self, name):
        """ Return True if stored procudure exist, otherwise return False """
        self.dbc.execute("SELECT prosrc FROM pg_proc WHERE proname='{name}';".format(
            name=name))
        return bool(self.dbc.fetchall())

    def _create_sp(self, name):
        """ Create stored procedure with given name """
        get_audit_sp = """
            CREATE OR REPLACE FUNCTION {name} (IN hostIdparam INT) RETURNS 
                                table (
                                    clock TIMESTAMP WITH TIME ZONE,
                                    hostName varchar(128),
                                    itemId bigint,
                                    value numeric(16,14),
                                    temUnits varchar(255),
                                    itemType int,
                                    itemName varchar(255),
                                    itemKey varchar(255),
                                    itemDelay varchar(1027),
                                    itemHistory varchar(255),
                                    itemValueType integer
                                )
                                AS $$
                                BEGIN
                                RETURN QUERY(SELECT 
                                                to_timestamp(hi.clock) as clock,
                                                ho.host As hostName,
                                                i.itemid AS itemId,
                                                hi.value AS value,
                                                i.units AS itemUnits,
                                                i.type AS itemType,
                                                i.name AS itemName,
                                                i.key_ AS itemKey,
                                                i.delay AS itemDelay,
                                                i.history AS itemHistory,
                                                i.value_type AS itemValueType
                                                FROM history hi
                                                LEFT JOIN items i ON hi.itemid = i.itemid
                                                LEFT JOIN hosts ho ON ho.hostid = i.hostid
                                                WHERE ho.hostid = hostIdparam
						limit 10
                                            );
            END; $$ LANGUAGE plpgsql;
        """.format(name=name)
        self.dbc.execute(get_audit_sp)

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.db.close()

    def read(self):
        """ Return list of tuples with audit records """

        self.dbc.callproc(self.sp_name, [zabbixhost_conf['zhostid']])

        result = []
        #for res in self.dbc.stored_results():
        result.extend(self.dbc.fetchall())
        return result

class SplunkIndex(object):
    """ Object wrapper for write data to splunk index """

    def __init__(self, splunk_conf, splunk_evt, splunk_index):
        self.splunk = client.connect(**splunk_conf)
        if not splunk_index in self.splunk.indexes:
            self.index = self.splunk.indexes.create(splunk_index)
        else:
            self.index = self.splunk.indexes[splunk_index]
        self.socket = self.index.attach(**splunk_evt)

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.socket.close()

    def write(self, data):
        """ Write data to splunk index, and return last written actionid """
        result = 0
        for row in data:
            text = "date='{0}', account='{1}', ip='{2}', action='{3}', type='{4}', name='{5}'".format(*row)
            if len(row) > 6 and not None in row[6:7]:
                text += ", old='{6}', new='{7}'".format(*row)
            log.info(text)
            text += " \r\n"
            self.socket.send(text.encode())
            result = data[0][len(data[0])-1]
        return result


def loadFromFile(filename):
    """ Helper function: load one integer from file """

    result = 0
    try:
        with open(filename, 'r') as f:
            result = int(f.read())
    except:
        log.info("Can't read file")
    finally:
        return result

def saveToFile(filename, data):
    """ Helper function: save data to file """
    try:
        with open(filename, 'w') as f:
            f.write('{0}'.format(data))
    except:
        log.info("Can't write to file")

def argParser():
    """ Helper function: return parsed arguments """
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--zhost', required=True, help='Zabbbix DB host')
    argparser.add_argument('--zdb', required=True, help='Zabbbix DB name')
    argparser.add_argument('--zuser', required=True, help='Zabbbix DB user')
    argparser.add_argument('--zpass', required=True, help='Zabbbix DB passowrd')
    argparser.add_argument('--zhostid', required=True, help='Zabbbix Host id (from inventory)')
    argparser.add_argument('--shost', required=True, help='Splunk host')
    argparser.add_argument('--sindex', required=True, help='Splunk Index name')
    argparser.add_argument('--suser', required=True, help='Splunk user')
    argparser.add_argument('--spass', required=True, help='Splunk password')
    argparser.add_argument('--host', required=True, help='Name of host will be showed in Splunk')
    argparser.add_argument('--continue', type=int, help='Action ID in zabbix db, to continue from')
    return  vars(argparser.parse_args())

if __name__ == '__main__':

    log = logging.getLogger(__name__)
    logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] %(message)s',
            datefmt='%d/%m/%Y %H:%M:%S')

    # get arguments
    args = argParser()

    zabbixdb_conf = {
            'host': args['zhost'],
            'database': args['zdb'],
            'user': args['zuser'],
            'password': args['zpass'],
    }

    zabbixhost_conf = {
            'zhostid': args['zhostid'],
    }

    splunk_conf = {
            'host': args['shost'],
            'username': args['suser'],
            'password': args['spass'],
    }

    splunk_evt = {
            'sourcetype': 'zabbix-history',
            'source': 'zabbix-db',
            'host': args['host'],
    }

    splunk_index = args['sindex']

    # Load actionid from which we should continue work.
    tmpFile = '/tmp/zabbixaudit'
    if 'continue' in args and args['continue'] != None:
        continueFrom = args['continue']
    else:
        continueFrom = loadFromFile(tmpFile)
    log.info('Continue from event %d', continueFrom)

    # Get audit log from zabbix and send it to splunk
    with ZabbixAudit(zabbixdb_conf,zabbixhost_conf, continueFrom) as db:
        with SplunkIndex(splunk_conf, splunk_evt, splunk_index) as splunk:
            data = db.read()
            continueFrom = splunk.write(data)
            log.info('%d events was added to splunk index[%s]', len(data), splunk_index)

            if continueFrom:
                # Save last actionid to continue with at next run.
                saveToFile(tmpFile, continueFrom)
