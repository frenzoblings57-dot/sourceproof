import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import sourceproof


class SourceProofTests(unittest.TestCase):
    def test_private_hosts_are_rejected(self):
        with self.assertRaises(ValueError):
            sourceproof.validate_url("http://127.0.0.1:8080/health")

    def test_invalid_request_is_rejected(self):
        with self.assertRaises(ValueError):
            sourceproof.verify({"claim": "hello", "sources": []})

    @patch("sourceproof.fetch_source")
    def test_supported_claim_returns_evidence(self, fetch):
        fetch.return_value = {
            "url": "https://example.com",
            "title": "Official page",
            "text": "Pocket Network publishes data services for AI agents.",
            "retrieved_at": "2026-11-23T00:00:00Z",
        }
        result = sourceproof.verify({
            "claim": "Pocket Network publishes data services for AI agents",
            "sources": ["https://example.com"],
        })
        self.assertEqual(result["verdict"], "supported")
        self.assertEqual(len(result["evidence"]), 1)
        self.assertGreater(result["evidence"][0]["coverage"], 0.5)

    @patch("sourceproof.fetch_source")
    def test_source_errors_do_not_hide_valid_results(self, fetch):
        fetch.side_effect = [RuntimeError("timeout"), {
            "url": "https://example.org", "title": "", "text": "The claim is true", "retrieved_at": "now"
        }]
        result = sourceproof.verify({"claim": "The claim is true", "sources": ["https://example.com", "https://example.org"]})
        self.assertEqual(len(result["source_errors"]), 1)
        self.assertEqual(result["verdict"], "supported")


if __name__ == "__main__":
    unittest.main()
