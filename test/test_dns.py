#!/usr/bin/env python
import os
import pprint
import socket
import sys
import json
import boto3
import logging
import cfn_flip
import argparse
import ipaddress
import re
import tldextract
import dns.resolver, dns.reversename

pathname = os.path.abspath(__file__)
pathname = pathname[:pathname.rfind("/")]

ap = argparse.ArgumentParser(add_help=True)
ap.add_argument("--route53", action="store_true", default=False, required=False, help="Check template records against route53 DNS servers")
ap.add_argument("--not-authoritative", action="store_false", default=True, required=False, help="Do not check template records against authoritative DNS servers")
ap.add_argument("--resolve", dest="resolv_conf_path", required=False, default="{}/resolv.conf".format(pathname), help="Path to resolv.conf style file to use for DNS config.")
ap.add_argument("-c", dest="route53_template_path", required=True, help="Path to template file to check.")
try:
    args = vars(ap.parse_args())
except:
    exit(1)

check_aws = False
aws_profile_name = "dns-admin"
aws_role_arn = "arn:aws:iam::421185999766:role/AccountAdmin"

class AnsiColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    LIGHTBLUE = '\033[34m'
    YELLOW = '\033[33m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def coloredConsoleLogging(fn):
    # add methods we need to the class
    def new(*args):
        levelno = args[1].levelno
        if(levelno>=50):
            color = AnsiColors.FAIL
        elif(levelno>=40):
            color = AnsiColors.FAIL
        elif(levelno>=30):
            color = AnsiColors.WARNING
        elif(levelno>=20):
            color = AnsiColors.OKGREEN
        elif(levelno>=10):
            color = AnsiColors.LIGHTBLUE
        else:
            color = AnsiColors.LIGHTBLUE
        args[1].msg = color + args[1].msg + AnsiColors.ENDC # normal
        return fn(*args)
    return new

def nearlyEqual(a, b, allowed_delta):
    return abs(a - b) <= allowed_delta

def getRoute53Client():
    try:
        session = boto3.session.Session(profile_name=aws_profile_name)
    except:
        etype, evalue, etb = sys.exc_info()
        logger.error("Could not create aws base client. Exception: %s, Error: %s." % (etype, evalue))
        return False
    sts_client = session.client('sts')
    try:
        assumedRoleObject = sts_client.assume_role(RoleArn=aws_role_arn,
                                                   RoleSessionName="AssumeRoleSession1")
    except:
        etype, evalue, etb = sys.exc_info()
        logger.error("Could not assume role. Exception: %s, Error: %s." % (etype, evalue))
        return False
    credentials = assumedRoleObject['Credentials']
    try:
        route_53_client = boto3.client('route53', aws_access_key_id=credentials['AccessKeyId'],
                                       aws_secret_access_key=credentials['SecretAccessKey'],
                                       aws_session_token=credentials['SessionToken'])
    except:
        etype, evalue, etb = sys.exc_info()
        logger.error("Could not create aws route53 client. Exception: %s, Error: %s." % (etype, evalue))
        return False
    return route_53_client

def getHostedZonesInfo(route_53_client):
    hosted_zones_ids = {}
    try:
        zones = route_53_client.list_hosted_zones()
    except:
        etype, evalue, etb = sys.exc_info()
        logger.error("Could not get hosted zones. Exception: %s, Error: %s." % (etype, evalue))
        return hosted_zones_ids
    for zone in zones.get('HostedZones'):
        hosted_zones_ids[zone['Name']] = zone['Id']
    return hosted_zones_ids

def getHostedZoneNameServers(route_53_client, zone_id):
    try:
        zone_info = route_53_client.get_hosted_zone(Id=zone_id)
    except:
        etype, evalue, etb = sys.exc_info()
        logger.error("Could not get hosted zone data for zone id %s. Exception: %s, Error: %s." % (zone_id, etype, evalue))
        return False
    nameservers = zone_info['DelegationSet']['NameServers']
    nameservers_ip = []
    for nameserver in nameservers:
        try:
            nameservers_ip.append(socket.gethostbyname(nameserver))
        except:
            etype, evalue, etb = sys.exc_info()
            logger.error("Could not get ipaddress for dns server %s. Exception: %s, Error: %s." % (nameserver, zone_id, etype, evalue))
    return nameservers_ip

def getAwsDnsAnswer(route_53_client, zone_id, record_name, record_type):
    return route_53_client.test_dns_answer(HostedZoneId=zone_id, RecordName=record_name, RecordType=record_type)

def readCloudformationTemplate(path_to_file):
    template = None
    try:
        with open(path_to_file, "r") as file:
            raw_yaml = file.read()
    except:
        etype, evalue, etb = sys.exc_info()
        logger.error("Could not read config file %s. Exception: %s, Error: %s." % (path_to_file, etype, evalue))
        return False
    try:
        # We convert the raw yaml to json to prevent unknown tag errors for unknown tags, e.g. "!Ref"
        raw_json = cfn_flip.to_json(raw_yaml)
        template = json.loads(raw_json)
    except:
        etype, evalue, etb = sys.exc_info()
        logger.error("Could not parse config file %s. Exception: %s, Error: %s." % (path_to_file, etype, evalue))
        sys.exit(1)
    return template

def getCurrentNameServerForDomain(resolver, domain):
        name_server_ips = []
        ns = resolver.nameservers[0]
        n = domain.split('.')
        for i in range(len(n), 0, -1):
            sub = '.'.join(n[i - 1:])

            logger.debug('Looking up %s on %s' % (sub, ns))
            query = dns.message.make_query(sub, dns.rdatatype.NS)
            response = dns.query.udp(query, ns)

            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                if rcode == dns.rcode.NXDOMAIN:
                    raise Exception('%s does not exist.' % (sub))
                else:
                    raise Exception('Error %s' % (dns.rcode.to_text(rcode)))

            if len(response.authority) > 0:
                rrsets = response.authority
            elif len(response.additional) > 0:
                rrsets = [response.additional]
            else:
                rrsets = response.answer

            # Handle all RRsets, not just the first one
            for rrset in rrsets:
                for rr in rrset:
                    if rr.rdtype == dns.rdatatype.SOA:
                        logger.debug('Same server is authoritative for %s' % (sub))
                    elif rr.rdtype == dns.rdatatype.A:
                        ns = rr.items[0].address
                        logger.debug('Glue record for %s: %s' % (rr.name, ns))
                    elif rr.rdtype == dns.rdatatype.NS:
                        authority = rr.target
                        ns = resolver.query(authority).rrset[0].to_text()
                        logger.debug('%s [%s] is authoritative for %s; ttl %i' % (authority, ns, sub, rrset.ttl))
                        result = rrset
                    else:
                        # IPv6 glue records etc
                        # log('Ignoring %s' % (rr))
                        pass
        aws_is_authoritative = False
        for record in result.items:
            if 'awsdns' in record.to_text():
                aws_is_authoritative = True
            ns_a_record = resolver.query(record.to_text(), 'A')
            name_server_ips.append(ns_a_record[0].to_text())
        return [aws_is_authoritative, name_server_ips]

def _getCurrentNameServerForDomain(resolver, domain_name):
    name_server_ips = []
    response = []
    try:
        response = resolver.query(domain_name, 'NS')
    except:
        etype, evalue, etb = sys.exc_info()
        logger.error("Could not get authoritative nameservers for domain {}. Exception: {}, Error: {}.".format(domain_name, etype, evalue))
    aws_is_authoritative = False
    for record in response:
        if 'awsdns' in record.to_text():
            aws_is_authoritative = True
        ns_a_record = resolver.query(record.to_text(), 'A')
        name_server_ips.append(ns_a_record[0].to_text())
    return [aws_is_authoritative, name_server_ips]

def compareRecordsDefault(template_record, live_record):
    if template_record.lower() == live_record.to_text().lower():
        return True
    return False

def compareARecords(template_record, live_record):
    return compareRecordsDefault(template_record, live_record)

def compareMXRecords(template_record, live_record):
    return compareRecordsDefault(template_record, live_record)

def compareCNAMERecords(template_record, live_record):
    entries_are_equal = compareRecordsDefault(template_record, live_record)
    # Try again with trailing dot.
    if not entries_are_equal and not template_record.endswith('.'):
        entries_are_equal = compareRecordsDefault(template_record + ".", live_record)
    return entries_are_equal

def compareSRVRecords(template_record, live_record):
    return compareRecordsDefault(template_record, live_record)

def compareAAAARecords(template_record, live_record):
    result = compareRecordsDefault(template_record, live_record)
    if result:
        return True
    # If default comparison failed, try compressed ip addresses.
    try:
        template_record = template_record.decode('utf8')
    except AttributeError:
        pass
    try:
        live_record = live_record.to_text().decode('utf8')
    except AttributeError:
        live_record = live_record.to_text()
    return ipaddress.ip_address(template_record).compressed == ipaddress.ip_address(live_record).compressed

def compareTXTRecords(template_record, live_record):
    live_record_txt = live_record.to_text()
    # Try unchanged raw entries first.
    if template_record == live_record_txt:
        return True
    # Try with double quotes removed.
    template_record = template_record.replace('"', '')
    live_record_txt = live_record_txt.replace('"', '')
    if template_record == live_record_txt:
        return True
    # Try with single whitspaces replaced with "+"-
    if re.sub(r"(?<!\s)\s(?!\s+)", "+", template_record) == live_record_txt:
        return True
    # Try again, with double whitespaces replaced by single whitespaces.
    if " ".join(template_record.split()) == " ".join(live_record.strings[0].decode().split()):
        return True
    return False

def compareMultipleAliasRecords(a_records, alias_records):
    correct_counter = 0
    a_record_ips = set([_.to_text() for _ in a_records])
    alias_record_ips = set([_.to_text() for _ in alias_records])
    return a_record_ips == alias_record_ips

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])
if sys.stdout.isatty():
    logging.StreamHandler.emit = coloredConsoleLogging(logging.StreamHandler.emit)
logger = logging.getLogger("DNSTester")

# Read template.
template = readCloudformationTemplate(args['route53_template_path'])
if not template:
    sys.exit(1)

# Get zone name from tempalte.
template_zone_name = None

for template_dns_entry in template['Resources'].items():
    if template_dns_entry[1]['Type'] == 'AWS::Route53::HostedZone':
        template_zone_name = template_dns_entry[1]['Properties']['Name']
        break

if not template_zone_name:
    logger.error("Could not get hosted zone name. Exiting.")
    sys.exit(1)

if os.path.isfile(args['resolv_conf_path']):
    logger.warning("Using custom resolv.conf file from {}".format(args['resolv_conf_path']))
    resolver = dns.resolver.Resolver(args['resolv_conf_path'])
else:
    resolver = dns.resolver.Resolver()

# Force nameservers to public reachable ones since in aws env the nameserver
# settings seem to be too resrictive.
resolver.nameservers = ['8.8.8.8', '9.9.9.9', '1.1.1.1']

nameservers_to_check = {}

# Get authoritative nameservers if configured to check these.
if args['not_authoritative']:
    aws_is_authoritative, authoritative_name_servers = getCurrentNameServerForDomain(resolver, template_zone_name)
    if not authoritative_name_servers:
        logger.error("Could not get authoritative name servers for domain {}. Exiting.".format(template_zone_name))
        exit(1)
    nameservers_to_check['Authoritative'] = authoritative_name_servers

# Get route53 hosted zone nameservers if configured to check these.
if args['route53']:
    route_53_client = getRoute53Client()
    if not route_53_client:
        exit(1)
    # Get hosted zones and their ids from aws.
    hosted_zones_info = getHostedZonesInfo(route_53_client)
    if not hosted_zones_info:
        exit(1)
    hosted_zone = None
    if template_zone_name not in hosted_zones_info:
        logger.error("Could not get zone info for {} from aws hosted zones. Exiting.".format(template_zone_name))
        exit(1)
    hosted_zones_id = hosted_zones_info[template_zone_name]
    hosted_zone_nameservers = getHostedZoneNameServers(route_53_client, hosted_zones_id)
    if not hosted_zone_nameservers:
        exit(1)
    nameservers_to_check['Route53'] = hosted_zone_nameservers

for nameserver_key, nameservers in nameservers_to_check.items():
    logger.info("{}: Querying nameservers: {}".format(nameserver_key, nameservers))

warnings = []
errors = []
dns_domain_paths = []

for template_dns_entry in template['Resources'].items():
    template_dns_entry_properties = template_dns_entry[1]['Properties']
    # Alias records my occur in different places in the yml structure.
    if 'AliasTarget' in template_dns_entry_properties or ('RecordSets' in template_dns_entry_properties and 'AliasTarget' in template_dns_entry_properties['RecordSets'][0]):
        if 'AliasTarget' in template_dns_entry_properties:
            alias_source = template_dns_entry_properties['Name']
            alias_type = template_dns_entry_properties['Type']
            alias_target = template_dns_entry_properties['AliasTarget']['DNSName']
        else:
            alias_source = template_dns_entry_properties['RecordSets'][0]['Name']
            alias_type = template_dns_entry_properties['RecordSets'][0]['Type']
            alias_target = template_dns_entry_properties['RecordSets'][0]['AliasTarget']['DNSName']
        if not aws_is_authoritative and 'Route53' not in nameservers_to_check:
            logger.warning("Found A record alias config in template but no Route53 DNS servers. Skipping.")
            continue
        # Resolve alias target.
        # Route53 allows for A RR records to point to an alias instead of an ip address.
        # To check these types of records, we first resolve the dns name and the alias
        # target to an ip address and compare these two.
        # If these do not match, we try to get an PTR record for it and compare it
        # with the configured alias target.
        if aws_is_authoritative:
            resolver.nameservers = nameservers_to_check['Authoritative']
        else:
            resolver.nameservers = nameservers_to_check['Route53']
        nameserver_buffer = resolver.nameservers
        template_record_set = template_dns_entry[1]['Properties']
        try:
            a_records = resolver.query(alias_source, alias_type)
        except:
            etype, evalue, etb = sys.exc_info()
            msg = "{}: Could not resolve {} {} record. Exception: {}, Error: {}.".format(nameserver_key, alias_source, alias_type, etype, evalue)
            logger.error(msg)
            errors.append(msg)
            continue
        try:
            resolver.nameservers = ['8.8.8.8', '9.9.9.9', '1.1.1.1']
            alias_records = resolver.query(alias_target, alias_type)
        except:
            etype, evalue, etb = sys.exc_info()
            msg = "{}: Could not resolve alias {} {} record. Exception: {}, Error: {}.".format(nameserver_key, alias_target, alias_type, etype, evalue)
            logger.error(msg)
            errors.append(msg)
            continue
        finally:
            resolver.nameservers = nameserver_buffer
        if len(alias_records) == 1:
            # If we only have one alias ip address, chances are very high that we face a dns loadbalancing by changing
            # the ip address on every query for the domain. To fix this, we try to compare the PTR records.
            alias_source_reversename = dns.reversename.from_address(a_records[0].to_text())
            alias_target_reversename = dns.reversename.from_address(alias_records[0].to_text())
            alias_ptr = False
            alias_source_ptr = []
            alias_target_ptr = []
            try:
                resolver.nameservers = ['8.8.8.8', '9.9.9.9', '1.1.1.1']
                alias_source_ptr = resolver.query(alias_target_reversename, "PTR")
                alias_target_ptr = resolver.query(alias_target_reversename, "PTR")
            except dns.resolver.NXDOMAIN:
                pass
            except:
                etype, evalue, etb = sys.exc_info()
                msg = "{}: Could not resolve PTR record for ips {} {}. Exception: {}, Error: {}.".format(nameserver_key, a_records[0].to_text(), alias_records[0].to_text(), etype, evalue)
                logger.warning(msg)
                warnings.append(msg)
            finally:
                resolver.nameservers = nameserver_buffer
            if alias_source_ptr and alias_target_ptr and alias_source_ptr[0].to_text() == alias_target_ptr[0].to_text():
                entries_are_equal = True
            else:
                entries_are_equal = False
        else:
            entries_are_equal = compareMultipleAliasRecords(a_records, alias_records)
        if not entries_are_equal:
            msg = "{}: Name {}({} record alias) does not match ServerValue: {} - MIGHT STILL BE OK".format(nameserver_key, alias_source, alias_type, alias_target)
            logger.warning(msg)
            logger.warning("AliasSource: {} - AliasTarget: {}".format([_.to_text() for _ in a_records], [_.to_text() for _ in alias_records]))
            warnings.append(msg)
        else:
            logger.info("{}: Name {}({} record alias) matches ServerValue: {} - OK".format(nameserver_key, alias_source, alias_type, alias_target))
    elif 'RecordSets' in template_dns_entry[1]['Properties']:
        for template_record_set in template_dns_entry[1]['Properties']['RecordSets']:
            template_record_type = template_record_set['Type']
            if 'ResourceRecords' in template_record_set:
                # Test if the subdomain path is complete.
                subdomain_path_is_complete = True
                for template_resource_record in template_record_set['ResourceRecords']:
                    if template_record_type in ["A", "AAAA", "CNAME"]:
                        if template_record_set['Name'] not in dns_domain_paths:
                            dns_domain_paths.append(template_record_set['Name'])
                        domain_parts = tldextract.extract(template_record_set['Name'])
                        if domain_parts.subdomain and domain_parts.subdomain.count(".") > 0:
                            subdomains = domain_parts.subdomain.split(".")[1:]
                            subdomain_path = "{}.{}".format(domain_parts.domain, domain_parts.suffix)
                            for subdomain in reversed(subdomains):
                                subdomain_path = "{}.{}".format(subdomain, subdomain_path)
                                if not subdomain_path.endswith('.'):
                                    subdomain_path += '.'
                                if subdomain_path not in dns_domain_paths:
                                    subdomain_path_is_complete = False
                                    msg = "Subdomain path for {} is incomplete.".format(template_record_set['Name'])
                                    warnings.append(msg)
                                    logger.warning(msg)
                                    break
                if not subdomain_path_is_complete:
                    continue
            for nameserver_key, nameservers in nameservers_to_check.items():
                resolver.nameservers = nameservers
                try:
                    live_records = resolver.query(template_record_set['Name'], template_record_type)
                except:
                    etype, evalue, etb = sys.exc_info()
                    msg = "{}: Could not resolve {} record for domain {}. Exception: {}, Error: {}.".format(nameserver_key, template_record_type, template_record_set['Name'], etype, evalue)
                    logger.error(msg)
                    errors.append(msg)
                    # Try to get alternative.
                    if template_record_type in ["A", "AAAA", "CNAME"]:
                        live_record = False
                        try:
                            live_record = resolver.query(template_record_set['Name'])
                        except:
                            pass
                        if live_record:
                            try:
                                msg = "{}: Found {} record with {} instead.".format(nameserver_key, dns.rdatatype.to_text(live_record.rdtype), live_record.response.answer[0].items[0].to_text())
                                logger.error(msg)
                                errors.append(msg)
                            except AttributeError:
                                pass
                    continue
                # TTL check disabled.
                #if not nearlyEqual(int(template_record_set['TTL']), int(live_records.rrset.ttl), 60):
                #    msg = "{}: {}({}) TTL differ. Template: {}, Live: {}".format(nameserver_key, template_record_set['Name'], template_record_type, template_record_set['TTL'], live_records.rrset.ttl)
                #    logger.warning(msg)
                #    warnings.append(msg)
                for template_resource_record in template_record_set['ResourceRecords']:
                    entries_are_equal = False
                    for live_record in live_records:
                        try:
                            entries_are_equal = getattr(sys.modules[__name__], "compare{}Records".format(template_record_type))(template_resource_record, live_record)
                        except AttributeError:
                            etype, evalue, etb = sys.exc_info()
                            logger.warning("Could not find compare{}Records function to test record set. Skipping.".format(template_record_type))
                            logger.warning("Exception: %s, Error: %s." % (etype, evalue))
                            continue
                        if entries_are_equal:
                            break
                    if not entries_are_equal:
                        if template_record_type != "TXT":
                            msg = "{}: Name {}({}): TemplateValue {} != ServerValue {} - NOT OK".format(nameserver_key, template_record_set['Name'], template_record_type, template_resource_record, live_record.to_text())
                            if not template_resource_record.endswith('.'):
                                msg += " - Maybe missing trailing dot?"
                        else:
                            msg = "{}: Name {}({}): TemplateValue {} could not be found in server TXT records - NOT OK".format(nameserver_key, template_record_set['Name'], template_record_type, template_resource_record, live_record.to_text())
                        logger.error(msg)
                        errors.append(msg)
                        continue
                    logger.info("{}: Name {}({}): TemplateValue {} == ServerValue: {} - OK".format(nameserver_key, template_record_set['Name'], template_record_type, template_resource_record, live_record.to_text()))

logger.info("Summary:")

if not errors and not warnings:
    logger.info("All OK.")
    sys.exit()

if warnings:
    logger.warning("Warnings: ")
    for warning in warnings:
        logger.warning(warning)

if not errors:
    sys.exit()

logger.error("Errors: ")
for error in errors:
    logger.error(error)
sys.exit(1)
