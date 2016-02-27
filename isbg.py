#!/usr/bin/env python

#
# Based on "isbg.py". Original header:
# This Python program scans an IMAP Inbox and runs every
# entry against SpamAssassin. For any entries that match,
# the message is copied to another folder, and the original
# marked or deleted.

# This software was mainly written Roger Binns
# <rogerb@rogerbinns.com> and maintained by Thomas Lecavelier
# <thomas@lecavelier.name> since novembre 2009.
# You may use isbg under any OSI approved open source license
# such as those listed at http://opensource.org/licenses/alphabetical

version="0.100-irq0"

import imaplib
import sys
import os
import subprocess
import argparse
import email
import fcntl
import keyring
import multiprocessing
import logging

def get_keyring_pass(server=None):
    return keyring.get_password("isbg-ng", server)

def parse_args(args):
    p = argparse.ArgumentParser(description="Bla")

    p.add_argument("--imaphost")
    p.add_argument("--imapuser")
    p.add_argument("--imapport", default="imap")
    p.add_argument("--imapinbox", default="IMAP")
    p.add_argument("--spaminbox", default="IMAP.spam")
    p.add_argument("--verbose", action="store_const", dest="loglevel", const=logging.INFO)
    p.add_argument("--debug", action="store_const", dest="loglevel", const=logging.DEBUG)
    p.add_argument("--quiet", action="store_const", dest="loglevel", const=logging.WARNING)
    p.add_argument("--num-processes", type=int, default=4)
    p.add_argument("--use-keyring", action="store_true")
    p.add_argument("--use-ssl", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--satest", default="spamassassin")
    p.add_argument("--state-dir", default=os.path.expanduser("~/.isbgng"))
    p.add_argument("--thresholdsize", type=int, default=1024*100,
                        help="Don't process larger messages")
    p.add_argument("--fetch-batch-size", type=int, default=25)

    r = p.parse_args(args)

    r.imappassword = get_keyring_pass(r.imaphost)
    if not r.imappassword:
        logging.error("Failed to get password from keyring")
        logging.info("To add password to keyring do: python -c 'import keyring; keyring.set_password(\"isbg-ng\", SERVERNAME, PASSWORD)'")
        sys.exit(1)

    if r.use_ssl:
        r.imapport = "imaps"

    r.state_dir = os.path.join(r.state_dir, r.imaphost, r.imapuser)
    r.past_uids_file = os.path.join(r.state_dir, "past_uids")
    r.lockfile = os.path.join(r.state_dir, "lock")

    return r

def lock_or_die(lockfile):
    with open(lockfile, "w") as fd:
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            logging.exception("Already running")
            sys.exit(42)

def make_statedir(statedir):
    if not os.path.isdir(statedir):
        try:
            os.makedirs(statedir)
            return True
        except:
            logging.exception("Can't create state dir")

def load_uids(filename):
    try:
        with open(filename, "r") as fd:
            return set((int(x) for x in fd.read().split()))
    except IOError:
        logging.info("Can't load uids file. Initializing empty")
        return set()

def save_uids(filename, uids):
    with open(filename, "w") as fd:
        fd.write(" ".join(str(x) for x in uids))

def imap_get_message(imap, uid):
    """Retrieve single message by uid"""
    status, msg = imap.uid("FETCH", uid, "(BODY.PEEK[])")

    if status != "OK" or (status == "OK" and msg == [None]):
        logging.error("Cound not fetch UID %r: %r", uid, msg)
        return False
    else:
        return msg[0][1]

def imap_connect(imaphost, imapport, use_ssl, imapuser, imappassword):
    if use_ssl:
        imap=imaplib.IMAP4_SSL(imaphost, imapport)
    else:
        imap=imaplib.IMAP4(imaphost,imapport)

    status, msg = imap.login(imapuser, imappassword)
    if status == "OK":
        logging.info("IMAP connected: %s", msg)
        return imap
    else:
        logging.error("IMAP connect failed: %s", msg)

def die():
    sys.exit(42)

def mailbox_exists(imap, mb):
    status, msg = imap.select(mb, readonly=True)
    if status == "OK":
        logging.debug("Mailbox %r OK", mb)
        return True
    else:
        logging.error("Selecting mb %r failed", mb)


def spamassassin_test_process(uid, satest, msg, loglevel):
    logger = multiprocessing.log_to_stderr()
    logger.setLevel(loglevel)

    logger.debug("Running spamassassin for %r", msg[:80])
    p = subprocess.Popen([satest, "--test-mode"],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         close_fds=True)

    stdout, stderr = p.communicate(msg)

    logger.debug("satest stdout[:30]: %r", stdout[:30])
    logger.debug("satest stderr[:30]: %r", stderr[:30])

    mail = email.message_from_string(stdout)

    is_spam = (mail["X-Spam-Flag"] == "YES")

    logger.info("Message %r subj: %r from: %r: %s",
                uid, mail["Subject"], mail["From"],
                ["HAM", "SPAM"][is_spam])
    logger.debug("Message %r subj: %r from: %r: %r",
                 uid, mail["Subject"], mail["From"],
                 mail["X-Spam-Status"])

    return (uid, is_spam)

def move_msg_to_spambox(imap, uid, spambox):
    status, msg = imap.uid("COPY", uid, spambox)
    if status == "OK":
        logging.debug("Copy %r OK: %s", spambox, msg)

        status, msg = imap.uid("STORE", uid, "+FLAGS.SILENT" , "(\\Deleted)")
        if status == "OK":
            logging.info("Successfully moved %r to %r", uid, spambox)
            return True

    logging.error("Failed to copy SPAM to %r", spambox)

def check_inbox(args, ignore_uids=set()):
    pool = multiprocessing.Pool(processes=args.num_processes)

    try:
        imap = imap_connect(args.imaphost, args.imapport, args.use_ssl,
                            args.imapuser, args.imappassword)

        if not imap:
            die()

        if not (mailbox_exists(imap, args.spaminbox) \
                and mailbox_exists(imap, args.imapinbox)):
            die()


        imap.select(args.imapinbox)

        status, uids = imap.uid("SEARCH", None,
                                "SMALLER", args.thresholdsize,
                                "UNSEEN")
        inbox_uids = set((int(x) for x in uids[0].split()))
        new_uids = inbox_uids - ignore_uids
        processed_uids = []

        logging.debug("Inbox UIDs: %r", inbox_uids)
        logging.debug("UIDs to ignore (saved): %r", ignore_uids)
        logging.debug("New UIDS: %r", new_uids)

        results = []
        for uid in new_uids:
            body = imap_get_message(imap, uid)
            if body:
                results.append(pool.apply_async(spamassassin_test_process, (uid, args.satest, body, args.loglevel)))
            else:
                logging.info("Failed to get message %r. Skipping", uid)

        pool.close()
        logging.info("Waiting for %s spamassassin workers to finish", len(results))
        pool.join()

        for result in results:
            if result.successful():
                uid, is_spam = result.get()
                if is_spam:
                    logging.info("Performing SPAM action for UID %r", uid)
                    if not args.dry_run:
                        move_msg_to_spambox(imap, uid, args.spaminbox)
                    else:
                        logging.warn("Dry run. Skipping spam action")
                else:
                    # no need to keep trace of spam UIDs as we move spam to spam folder
                    processed_uids.append(uid)
            else:
                logging.error("Spamassassin worker %r failed", result)

        imap.close()

        return set(processed_uids)
    except:
        logging.exception("")
        pool.terminate()

    finally:
        logging.info("Tearing down IMAP connection")
        imap.logout()

    return set()
def setup():
    args = parse_args(sys.argv[1:])

    if not make_statedir(args.state_dir):
        pass

    lock_or_die(args.lockfile)

    logging.basicConfig(level=args.loglevel)

    state = {
        "past_uids": load_uids(args.past_uids_file)
    }


    logging.debug("Arguments: %r", args)
    logging.debug("State: %r", state)

    return args, state

def teardown(args, state):
    save_uids(args.past_uids_file, state["past_uids"])

def main():
    args, state = setup()

    processed_uids = check_inbox(args, state["past_uids"])

    logging.info("Processed %s new messages", len(processed_uids))
    logging.debug("Processed messages: %r", processed_uids)
    state["past_uids"] |= processed_uids

    teardown(args, state)

if __name__ == '__main__':
    main()
