#!/bin/bash
# Simple test runner

echo "🧪 Running tests..."

# Run tests
.venv/bin/pytest tests/test_appsec.py -v

# Check exit code
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ Tests passed!"
else
    echo "❌ Tests failed"
fi
