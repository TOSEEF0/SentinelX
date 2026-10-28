"""
SentinelX QA Test Runner
Executes comprehensive test suites and generates a verification report.
"""
import unittest
import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def run_tests():
    start_time = time.time()
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover(start_dir=str(Path(__file__).parent), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    duration = time.time() - start_time

    print("\n" + "=" * 60)
    print("SENTINELX SECURITY AUDITOR QA VERIFICATION SUMMARY")
    print("=" * 60)
    print(f"Total Tests Executed : {result.testsRun}")
    print(f"Passed               : {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures             : {len(result.failures)}")
    print(f"Errors               : {len(result.errors)}")
    print(f"Skipped              : {len(result.skipped)}")
    print(f"Duration             : {duration:.2f} seconds")
    print("=" * 60)

    if result.wasSuccessful():
        print("STATUS: ALL TESTS PASSED SUCCESSFULLY [OK]")
        return 0
    else:
        print("STATUS: TEST SUITE REPORTED FAILURES [FAIL]")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
