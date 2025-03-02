# Tests
import unittest
from sympy import Integer
from shamir import SharingBuilder, ReconstructionBuilder, SecretSharing, Prime
import logging

## Test secret & prime
secret = Integer("156402071732811106507596152138279689577457410967997136623970051482223809533794")

class TestSecretSharing(unittest.TestCase):

    def setUp(self):
        self.secret = secret
        self.prime = Prime
        self.threshold = 5
        self.num_shares = 10
        self.seed = 42

    def test_generate_shares(self):
        secret_sharing = SecretSharing(SharingBuilder(self.secret, self.threshold, self.num_shares, self.prime, self.seed))
        self.assertEqual(len(secret_sharing.shares), self.num_shares)
        self.assertEqual(secret_sharing.secret, self.secret)

    def test_reconstruct_secret(self):
        secret_sharing = SecretSharing(SharingBuilder(self.secret, self.threshold, self.num_shares, self.prime, self.seed))
        reconstructed_secret = secret_sharing.reconstruct_secret()
        self.assertEqual(reconstructed_secret, self.secret)

    def test_select_threshold_shares(self):
        secret_sharing = SecretSharing(SharingBuilder(self.secret, self.threshold, self.num_shares, self.prime, self.seed))
        selected_shares = secret_sharing.select_threshold_shares()
        self.assertEqual(len(selected_shares.shares), self.threshold)
        reconstructed_secret = selected_shares.reconstruct_secret()
        self.assertEqual(reconstructed_secret, self.secret)

    def test_reshare_shares(self):
        secret_sharing = SecretSharing(SharingBuilder(self.secret, self.threshold, self.num_shares, self.prime, self.seed))
        reshared_sharing = secret_sharing.reshare_shares(self.threshold, self.num_shares, seed=53)
        reshared_reconstructed_secret = reshared_sharing.reconstruct_secret()
        self.assertEqual(reshared_reconstructed_secret, self.secret)

    def test_reconstruct_with_insufficient_shares(self):
        secret_sharing = SecretSharing(SharingBuilder(self.secret, self.threshold, self.num_shares, self.prime, self.seed))
        selected_shares = dict(list(secret_sharing.shares.items())[:self.threshold - 1])
        with self.assertRaises(ValueError):
            SecretSharing(ReconstructionBuilder(selected_shares, self.threshold, self.prime))

    def test_resharing(self):
        # Create a sharing scheme with t=2, n=3
        t = 5
        n = 10

        # Configure logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)

        logger.info(f"Starting resharing test with T={t} and N={n}")
        secret_sharing = SecretSharing(SharingBuilder(secret, t, n, Prime, seed=42))
        secret_sharing.display()
        reconstructed_secret = secret_sharing.reconstruct_secret()
        assert reconstructed_secret == secret

        # reshare the keys with all receipients
        logger.info("Resharing the keys with all recipients")
        reshared_sharing = secret_sharing.reshare_shares(t,n, seed=53)
        reshared_sharing.display()
        reshared_reconstructed_secret = reshared_sharing.reconstruct_secret()
        assert reshared_reconstructed_secret == secret

        # reshare only with threshold receipients
        logger.info("Resharing the keys with only threshold recipients")
        threshold_sharings = reshared_sharing.select_threshold_shares()
        logger.info("Threshold shares used for reconstruction")
        threshold_sharings.display()
        assert secret == threshold_sharings.reconstruct_secret()
        threshold_reshared_sharings = threshold_sharings.reshare_shares(t, n, seed=57)
        threshold_reshared_sharings.display()
        assert secret == threshold_reshared_sharings.reconstruct_secret();

        logger.info("Resharing test to change number of participants")
        threshold_reshared_sharings = threshold_sharings.reshare_shares(t, n+3, seed=589)
        threshold_reshared_sharings.display()
        assert secret == threshold_reshared_sharings.reconstruct_secret();

        logger.info("Resharing test to change number of participants and threshold")
        threshold_reshared_sharings = threshold_sharings.reshare_shares(t+3, n+3, seed=609)
        threshold_reshared_sharings.display()
        assert secret == threshold_reshared_sharings.reconstruct_secret()

        logger.info("Threshold reconstruction after reconfiguring n & t")
        threshold_sharings = threshold_reshared_sharings.select_threshold_shares();
        threshold_sharings.display()
        assert secret == threshold_sharings.reconstruct_secret()
        logger.info("Resharing tests done")

    def test_basic(self):
        t = 5
        n = 10
        secret_sharing = SecretSharing(SharingBuilder(secret, t, n, Prime, seed=42))
        secret_sharing.display()

        # reconstruct using all N shares
        reconstructed_secret = secret_sharing.reconstruct_secret()
        assert reconstructed_secret == secret, "The reconstructed secret does not match the original secret"

        # reconstruct using t of n shares.
        selected_shares = secret_sharing.select_threshold_shares()
        selected_shares.display()
        reconstructed_secret_from_threshold = selected_shares.reconstruct_secret()
        assert reconstructed_secret_from_threshold == secret, "The reconstructed secret from threshold shares does not match the original secret"



if __name__ == '__main__':
    unittest.main()
