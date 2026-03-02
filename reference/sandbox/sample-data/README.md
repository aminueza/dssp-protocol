# Sample Data

Place sample PDF files here for the demo. The minio-setup service will upload them
to the MinIO `dssp-documents` bucket on startup.

For testing, you can create a simple PDF:
```bash
echo "Sample bank statement - Account: 1234567890 - Balance: $50,000.00" | \
  enscript -p - | ps2pdf - sample-statement.pdf
```

Or use any PDF files you have available.
