#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
    client.py
    ~~~~~~~~~~~~~~

    Python test client for the Simplenote API

    :copyright: (c) 2011 by Daniel Schauenberg
    :license: MIT, see LICENSE for more details.
"""

import unittest
import os
import sys
sys.path.append(os.getcwd())
#Override NOTE_FETCH_LENGTH for testing purposes
import simplenote
simplenote.simplenote.NOTE_FETCH_LENGTH = 5
from simplenote import Simplenote, SimplenoteLoginFailed

class TestSimplenote(unittest.TestCase):

    def setUp(self):
        self.user = "test@test.com"
        self.password = "test"
        self.clear_all_notes()
        self.unicode_note = "∮ E⋅da = Q,  n → ∞, ∑ f(i) = ∏ g(i),      ⎧⎡⎛┌─────┐⎞⎤⎫"
        self.unicode_note_key = False
        note, status = Simplenote(self.user, self.password).get_note_list()
        self.initial_note_count = 0
        self.tag_note_count = 0
        self.first_note = False
        self.second_note = False
        note, status = Simplenote(self.user, self.password).add_note({"content": "First Note.", "tags": ["tag1"]})
        if status == 0:
            self.initial_note_count += 1
            self.tag_note_count += 1
            self.first_note = note['key']
        return
        note, status = Simplenote(self.user, self.password).add_note({"content": "Second Note.", "tags": ["tag1", "tag2"]})
        if status == 0:
            self.initial_note_count += 1
            self.tag_note_count += 1
            self.second_note = note['key']
        note, status = Simplenote(self.user, self.password).add_note(self.unicode_note)
        if status == 0:
            self.initial_note_count += 1
            self.unicode_note_key = note['key']

    def tearDown(self):
        self.clear_all_notes()

    def test_simplenote_auth(self):
        token = Simplenote(self.user, self.password).get_token()
        self.assertNotEqual(None, token)

    def test_simplenote_failed_auth(self):
        s = Simplenote(self.user, "")
        self.assertRaises(SimplenoteLoginFailed, s.get_token)

    # When get_list_length test fails unexpectedly it's due to a failure in
    # teardown to clear all notes.  Unfortunately there is no way to guarantee
    # all notes are cleared.  This test is more likely to fail as a result due
    # to the assertEqual requirements The next test also tests get_note_list
    # functionality so it makes no sense to let the whole suite fail so set as
    # expected failure.
    @unittest.expectedFailure
    def test_simplenote_get_list_length(self):
        res, status = Simplenote(self.user, self.password).get_note_list()
        if status == 0:
            self.assertEqual(self.initial_note_count, len(res))
        else:
            self.assertEqual(0, len(res))

    def test_simplenote_get_list_length_longer_than_note_fetch_length(self):
        while self.initial_note_count <= simplenote.simplenote.NOTE_FETCH_LENGTH+1:
            note, status = Simplenote(self.user, self.password).add_note("Note "+str(self.initial_note_count+1))
            if status == 0:
                self.initial_note_count += 1

        res, status = Simplenote(self.user, self.password).get_note_list()
        if status == 0:
            self.assertTrue(len(res) > simplenote.simplenote.NOTE_FETCH_LENGTH)

    def test_simplenote_get_list_with_tags(self):
        res, status = Simplenote(self.user, self.password).get_note_list(tags=["tag1"])
        if status == 0:
            self.assertEqual(self.tag_note_count, len(res))
        else:
            self.assertEqual(0, len(res))

    def test_simplenote_first_note(self):

        if self.first_note != False:
            note, status = Simplenote(self.user, self.password).get_note(self.first_note)
            if status == 0:
                self.assertTrue(type(note) == dict)
                self.assertEqual("First Note.", note["content"].split('\n')[0])

    def test_simplenote_second_note(self):
        if self.second_note != False:
            note, status = Simplenote(self.user,
                                    self.password).get_note(self.second_note)
            if status == 0:
                self.assertTrue(type(note) == dict)
                self.assertEqual("Second Note.", note["content"].split('\n')[0])

    def test_simplenote_trash_note(self):
        if self.first_note != False:
            note, status = Simplenote(self.user,
                                    self.password).trash_note(self.first_note)
            if status == 0:
                self.assertEqual(1, note["deleted"])

        if self.second_note != False:
            note, status = Simplenote(self.user,
                                    self.password).trash_note(self.second_note)
            if status == 0:
                self.assertEqual(1, note["deleted"])

    def test_simplenote_delete_note(self):
        if self.first_note != False:
            note, status = Simplenote(self.user,
                                    self.password).delete_note(self.first_note)
            if status == 0:
                note, status = Simplenote(self.user,
                                          self.password).get_note(self.first_note)
                self.assertEqual(-1, status)

        if self.second_note != False:
            note, status = Simplenote(self.user,
                                    self.password).delete_note(self.second_note)
            if status == 0:
                note, status = Simplenote(self.user,
                                          self.password).get_note(self.second_note)
                self.assertEqual(-1, status)

    def test_simplenote_add_note_object(self):
        res, status = Simplenote(self.user, self.password).add_note({"content":
                                                                     "new note"})
        if status == 0:
            note, status = Simplenote(self.user, self.password).get_note(res["key"])
            if status == 0:
                self.assertEqual("new note", note["content"])

    def test_simplenote_add_note_content(self):
        res, status = Simplenote(self.user, self.password).add_note("new note")
        if status == 0:
            note, status = Simplenote(self.user, self.password).get_note(res["key"])
            if status == 0:
                self.assertEqual("new note", note["content"])

    def test_simplenote_update_note(self):
        note = {}
        note['key'] = self.first_note
        note["content"] = "Updated Note."
        note, status = Simplenote(self.user, self.password).update_note(note)
        if status == 0:
            note, status = Simplenote(self.user, self.password).get_note(note["key"])
            if status == 0:
                self.assertEqual("Updated Note.", note["content"].split('\n')[0])

    def test_simplenote_is_unicode(self):
        if self.unicode_note_key != False:
            note, status = Simplenote(self.user,
                                    self.password).get_note(self.unicode_note_key)
            if status == 0:
                self.assertTrue(self.is_utf8(note["content"]))

    def test_note_with_plus_signs(self):
        note, status = Simplenote(self.user, self.password).add_note("++")
        if status == 0:
            note, status = Simplenote(self.user, self.password).get_note(note["key"])
            if status == 0:
                self.assertEqual("++", note["content"])

    def test_note_get_previous_version(self):
        note_v1, status = Simplenote(self.user, self.password).add_note("Hello")
        if status == 0:
            note_v2 = {}
            note_v2['key'] = note_v1["key"]
            note_v2["content"] = "Goodbye"
            note_v2, status = Simplenote(self.user, self.password).update_note(note_v2)
            if status == 0:
                if note_v2["version"] > 1:
                    note, status = Simplenote(self.user, self.password).get_note(note_v2["key"], note_v2["version"]-1)
                    if status == 0:
                        self.assertEqual("Hello", note["content"])

    def is_utf8(self, s):
        try:
            s.decode('utf-8')
            return True
        except UnicodeDecodeError:
            return False

    def clear_all_notes(self):
        res, status = Simplenote(self.user, self.password).get_note_list()
        while (len(res) > 0) and (status == 0):
            [Simplenote(self.user, self.password).delete_note(n["key"]) for n in res]
            res, status = Simplenote(self.user, self.password).get_note_list()

if __name__ == '__main__':
    unittest.main()

