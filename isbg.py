#!/usr/bin/env python
# -*- coding: utf-8 -*-
# UTF-8? ✓

# Original idea and basis for this was "isbg.py".
# Original header:
# This Python program scans an IMAP Inbox and runs every
# entry against SpamAssassin. For any entries that match,
# the message is copied to another folder, and the original
# marked or deleted.

# This software was mainly written Roger Binns
# <rogerb@rogerbinns.com> and maintained by Thomas Lecavelier
# <thomas@lecavelier.name> since novembre 2009.
# You may use isbg under any OSI approved open source license
# such as those listed at http://opensource.org/licenses/alphabetical

import imaplib
import sys
import os
import subprocess
import argparse
import fcntl
import keyring
import multiprocessing
import logging
import signal
import ssl
import email
import time

__author__ = "Marcel Lauhoff <ml@irq0.org>"
__version__ = "0.1"

log = logging.getLogger("MBA")
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(name)s] %(levelname)s: %(message)s')
console.setFormatter(formatter)
log.addHandler(console)

# = Configuration / Argument parsing =


def get_keyring_pass(server=None):
    return keyring.get_password("isbg-ng", server)


def parse_args(args):
    p = argparse.ArgumentParser(description="MBA - MailBoxAssassin")

    p.add_argument("--imaphost", help="IMAP server address")
    p.add_argument("--imapuser", help="IMAP username")
    p.add_argument("--imapport", default="imap",
                   help="IMAP server port (default: imap or imaps with --use-ssl)")
    p.add_argument("--imapinbox", default="IMAP",
                   help="IMAP mailbox to filter")
    p.add_argument("--spaminbox", default="SPAM",
                   help="IMAP mailbox to move spam to")
    p.add_argument("--verbose", action="store_const", dest="loglevel",
                   help="High level log messages",
                   const=logging.INFO)
    p.add_argument("--debug", action="store_const", dest="loglevel",
                   help="Low level debug messages (including imap lib)",
                   const=logging.DEBUG)
    p.add_argument("--num-processes", type=int,
                   default=multiprocessing.cpu_count(),
                   help="Number of spamassassin test processes to launch "
                   "(default: #cpus)")
    p.add_argument("--continuous", action="store_true",
                   help="Run continuously")
    p.add_argument("--pause-time", type=int,
                   default=5*60,
                   help="Pause time between filter runs (default: 5 mins)")
    p.add_argument("--use-ssl", action="store_true",
                   help="Use IMAPS (IMAP with SSL socket)")
    p.add_argument("--use-tls", action="store_true",
                   help="Use IMAP with STARTTLS")
    p.add_argument("--dry-run", action="store_true",
                   help="Don't move mail")
    p.add_argument("--spamassassin-bin", default="spamassassin",
                   help="Name of spamassassin binary")
    p.add_argument("--state-dir", default=os.path.expanduser("~/.cache/mbf/"),
                   help="Directory to store state")
    p.add_argument("--thresholdsize", type=int, default=1024*100,
                   help="Don't process larger messages (default: 100K)")

    r = p.parse_args(args)

    r.imappassword = get_keyring_pass(r.imaphost)
    if not r.imappassword:
        log.error("Failed to get password from keyring")
        log.info("To add password to keyring do: "
                 "python -c 'import keyring; "
                 "keyring.set_password(\"isbg-ng\", SERVERNAME, PASSWORD)'")
        sys.exit(1)

    if r.use_ssl:
        r.imapport = "imaps"

    if not r.loglevel:
        r.loglevel = logging.WARNING

    r.state_dir = os.path.join(r.state_dir, r.imaphost, r.imapuser)
    r.past_uids_file = os.path.join(r.state_dir, "past_uids")
    r.lockfile = os.path.join(r.state_dir, "lock")

    return r

# = State and Lock management helpers =


def lock_or_die(lockfile):
    "Die if lockfile already locked"
    with open(lockfile, "w") as fd:
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            log.exception("Already running")
            sys.exit(42)


def ensure_statedir(statedir):
    "Make sure that statedir exists"
    if not os.path.isdir(statedir):
        try:
            os.makedirs(statedir)
            return True
        except:
            log.exception("Can't create state dir")
            raise Exception("Can't create state dir")


def load_uids(filename):
    "Load list of uids serialized with save_uids"
    try:
        with open(filename, "r") as fd:
            return set((int(x) for x in fd.read().split()))
    except IOError:
        log.info("Can't load uids file. Initializing empty")
        return set()


def save_uids(filename, uids):
    "Save list of uids to filename"
    with open(filename, "w") as fd:
        fd.write(" ".join(str(x) for x in uids))


# = Spamassassin process runner =

def spamassassin_test_process(cfg, uid, msg):
    """
    Run spamassassin process and feed message to it.
    Return (uid, spam status)
    """
#    log = multiprocessing.log_to_stderr()
#    log.setLevel(cfg.loglevel)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    try:
        log.debug("Running spamassassin for %s", uid)
        p = subprocess.Popen([cfg.spamassassin_bin, "--test-mode"],
                             env={"LANG": "en_US.UTF-8",
                                  "LC_ALL": "en_US.UTF-8"},
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             close_fds=True)

        stdout, stderr = p.communicate(msg)

        log.debug("satest stdout[:30]: %r", stdout[:30])
        log.debug("satest stderr[:30]: %r", stderr[:30])

        if p.returncode != 0:
            raise Exception()

        mail = email.message_from_string(stdout.decode("UTF-8", "replace"))

        is_spam = (mail["X-Spam-Flag"] == "YES")

        log.info("Message %r subj: %r from: %r: %s",
                 uid, mail["Subject"], mail["From"],
                 ["HAM", "SPAM"][is_spam])
        log.debug("Message %r subj: %r from: %r: %r",
                  uid, mail["Subject"], mail["From"],
                  mail["X-Spam-Status"])
        return (uid, is_spam)

    except:
        log.exception("Spamassassin process failed for uid %s", uid)
        return (uid, None)


def spamassassin_mails(cfg, messages):
    """
    Pipe messages through spamasssassin worker processes
    """
    results = []
    try:
        pool = multiprocessing.Pool(processes=cfg.num_processes)
        for uid, msg in messages:
            if msg:
                results.append(pool.apply_async(spamassassin_test_process,
                                                (cfg, uid, msg)))
            else:
                log.info("Skipping empty message %r", msg)
    except:
        log.exception("Spamassassin run failed")
        pool.terminate()

    finally:
        pool.close()
        log.info("Waiting for %s spamassassin jobs to finish. "
                 "Running %s in parallel", len(results), cfg.num_processes)
        pool.join()

    return results


# = IMAP functions =

# == Exceptions and response checking ==

class IMAPCommandFailed(Exception):
    "IMAP Command did not execute with status OK"
    pass


class ServerConfigurationError(Exception):
    "Something on the IMAP server prevents us to work properly"
    pass


class ClientConfigurationError(Exception):
    "Something in our configuration does not work with the IMAP server"
    pass


def check_imap_response(resp):
    "Check IMAP response. Raise IMAPCommandFailed if it fails"
    status, msg = resp
    if status == "OK":
        log.debug("IMAP OK: %s", str(msg)[:80])
        return msg
    else:
        log.debug("IMAP command failed: %s %s", status, str(msg)[:80])
        raise IMAPCommandFailed(msg)


# == Utilities ==

def imap_get_message(imap, uid):
    """Retrieve single message by uid"""
    try:
        msg = check_imap_response(imap.uid("FETCH", str(uid), "(BODY.PEEK[])"))
        if msg == [None]:
            raise IMAPCommandFailed("Body is empty")

        return (uid, msg[0][1])

    except IMAPCommandFailed:
        log.exception("Cound not fetch UID %r", uid)


def imap_connect(cfg):
    """
    Connect and login to IMAP server using parameters from config
    object to set the various ssl/tls/plain combinations.
    """
    if cfg.use_ssl:
        imap = imaplib.IMAP4_SSL(cfg.imaphost, cfg.imapport)
    else:
        imap = imaplib.IMAP4(cfg.imaphost, cfg.imapport)

    if cfg.loglevel == logging.DEBUG:
        imap.debug = 4

    log.info("Connected")

    try:
        if cfg.use_tls:
            context = ssl.create_default_context()
            check_imap_response(imap.starttls(ssl_context=context))
            log.debug("STARTTLS succcessful")

    except Exception as e:
        log.exception("STARTTS failed. Tearing down IMAP connection")
        imap.shutdown()
        raise ServerConfigurationError("STARTTLS unsupported")

    try:
        check_imap_response(imap.login(cfg.imapuser, cfg.imappassword))

    except Exception as e:
        log.exception("Login failed. Tearing down IMAP connection")
        imap.logout()
        raise ClientConfigurationError("Login failed")

    return imap


def mailbox_exists(imap, mb):
    "Does mailbox mb exists?"
    try:
        return check_imap_response(imap.select(mb, readonly=True))
    except IMAPCommandFailed:
        return False


def move_msg_to_spambox(imap, uid, spambox):
    """
    Move message to spambox and mark as deleted in source mailbox.
    Assume that uid exists in the currently selected mailbox.
    """
    try:
        check_imap_response(imap.uid("COPY", str(uid), spambox))
        check_imap_response(imap.uid("STORE", str(uid), "+FLAGS.SILENT",
                                     "(\\Deleted)"))

        log.debug("Successfully moved %r to %r", uid, spambox)
        return True

    except IMAPCommandFailed as e:
        log.error("Failed to copy SPAM to %r: %s", spambox, e.message)


def find_new_uids(cfg, imap):
    """
    Find new uids to process in current mailbox
    """
    uids = check_imap_response(imap.uid("SEARCH", None,
                                        "SMALLER", str(cfg.thresholdsize),
                                        "UNSEEN"))

    return set((int(x) for x in uids[0].split()))


# = Main filter logic =

def check_inbox(cfg, ignore_uids=set()):
    imap = imap_connect(cfg)
    ham = []
    spam = []

    if not mailbox_exists(imap, cfg.spaminbox):
        raise ServerConfigurationError("SPAM mailbox ({}) does not exist".format(cfg.spaminbox))
    if not mailbox_exists(imap, cfg.imapinbox):
        raise ServerConfigurationError("IMAP inbox ({}) does not exist".format(cfg.imapinbox))

    try:
        check_imap_response(imap.select(cfg.imapinbox))

        inbox_uids = find_new_uids(cfg, imap)
        new_uids = inbox_uids - ignore_uids

        log.debug("Inbox UIDs: %r", inbox_uids)
        log.debug("UIDs to ignore (saved): %r", ignore_uids)
        log.debug("New UIDS: %r", new_uids)

        mails = [imap_get_message(imap, uid) for uid in new_uids]
        results = spamassassin_mails(cfg, mails)

        for result in results:
            if result.successful():
                uid, is_spam = result.get()

                if is_spam is True:
                    spam.append(uid)
                    log.info("Executing SPAM action for UID %r", uid)
                    if not cfg.dry_run:
                        move_msg_to_spambox(imap, uid,
                                            cfg.spaminbox)
                    else:
                        log.warn("Dry run. Skipping spam action")
                elif is_spam is False:
                    ham.append(uid)
            else:
                log.error("Spamassassin worker %r failed", result)
    except:
        log.exception("Error while processing mails")

    else:
        log.info("Successfuly processed mails in folder %s", cfg.imapinbox)

    finally:
        log.info("Tearing down IMAP connection")
        imap.close()
        imap.logout()

    return (set(spam), set(ham))


# = Start / Teardown / Run


def setup(cfg):
    "Setup program state from state file and config"

    log.debug("Config: %r", cfg)

    ensure_statedir(cfg.state_dir)

    lock_or_die(cfg.lockfile)

    log.setLevel(level=cfg.loglevel)

    state = {
        "past_uids": load_uids(cfg.past_uids_file)
    }

    log.debug("State: %r", state)

    return state


def teardown(cfg, state):
    "Persist program state"
    save_uids(cfg.past_uids_file, state["past_uids"])


def run_once(cfg):
    "Setup, run, teardown. Manage state"
    state = setup(cfg)
    try:
        spam, ham = check_inbox(cfg, state["past_uids"])

        log.info("Processed %s new messages: %s spam, %s ham",
                 len(spam)+len(ham), spam, ham)
        log.debug("Marked as ham: %r", ham)
        log.debug("Marked as spam: %r", spam)
        # only remember ham uids, as we moved the spam mails
        # to another folder
        state["past_uids"] |= ham
    except ServerConfigurationError as e:
        log.error("Problem with server configuration detected: %s",
                  e.args[0])
    finally:
        teardown(cfg, state)


def main(argv):
    try:
        cfg = parse_args(argv[1:])
    except ValueError as e:
        log.error("Error in arguments / keyring credentials: %s", e.args[0])
        sys.exit(1)
    except:
        sys.exit(1)

    try:
        if cfg.continuous:
            while True:
                run_once(cfg)

                log.debug("Sleeping %s seconds for the next run",
                          cfg.pause_time)
                time.sleep(cfg.pause_time)

        else:
            run_once(cfg)
    except KeyboardInterrupt as e:
        sys.exit(1)


if __name__ == '__main__':
    main(sys.argv)
