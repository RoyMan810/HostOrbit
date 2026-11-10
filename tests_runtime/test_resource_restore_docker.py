from pathlib import Path
import unittest
from unittest.mock import patch

from hostorbit.errors import Denied
from hostorbit.runtime.resource_restore_docker import _copy_to_volume


class RestoreDockerTests(unittest.TestCase):
    def test_changed_reserved_target_prevents_start(self):
        container = "c" * 64
        with (patch("hostorbit.runtime.resource_restore_docker._docker", side_effect=[container, container]) as docker,
              patch("hostorbit.runtime.resource_restore_docker.check_restore_target",
                    side_effect=[{"target_fingerprint": "f" * 64}, Denied("RESTORE_TARGET_CHANGED")]) as check):
            with self.assertRaisesRegex(Denied, "RESTORE_TARGET_CHANGED"):
                _copy_to_volume(Path("/safe"), "new-volume", {"reservation": "1" * 32}, {})
        self.assertEqual([call.args[1] for call in docker.call_args_list], ["create", "rm"])
        self.assertEqual(check.call_args.kwargs["expected_container"], container)
        self.assertEqual(check.call_args.kwargs["expected_fingerprint"], "f" * 64)

    def test_expired_procedure_prevents_start(self):
        container = "c" * 64
        with (patch("hostorbit.runtime.resource_restore_docker._docker", side_effect=[container, container]) as docker,
              patch("hostorbit.runtime.resource_restore_docker.check_restore_target",
                    return_value={"target_fingerprint": "f" * 64}),
              patch("hostorbit.runtime.resource_restore_docker.time.time", return_value=200)):
            with self.assertRaisesRegex(Denied, "RESTORE_ATTESTATION_EXPIRED"):
                _copy_to_volume(Path("/safe"), "new-volume", {"reservation": "1" * 32},
                                {"tested_at": 100, "expires_at": 200})
        self.assertEqual([call.args[1] for call in docker.call_args_list], ["create", "rm"])

    def test_uncertain_start_keeps_the_helper_for_reconciliation(self):
        with (patch("hostorbit.runtime.resource_restore_docker._docker",
                    side_effect=["c" * 64, Denied("RESTORE_DOCKER_OUTCOME_UNKNOWN"), "unexpected"]) as docker,
              patch("hostorbit.runtime.resource_restore_docker.check_restore_target",
                    return_value={"target_fingerprint": "f" * 64}),
              patch("hostorbit.runtime.resource_restore_docker.time.time", return_value=100)):
            with self.assertRaisesRegex(Denied, "RESTORE_DOCKER_OUTCOME_UNKNOWN"):
                _copy_to_volume(Path("/safe"), "new-volume", {"reservation": "1" * 32},
                                {"tested_at": 100, "expires_at": 200})
        self.assertEqual([call.args[1] for call in docker.call_args_list], ["create", "start"])
