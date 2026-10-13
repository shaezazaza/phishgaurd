#!/usr/bin/env bash
# Downloads the public datasets used for training into ../data (about 2.7 GB, mostly phishing_pot).
set -e
mkdir -p ../data && cd ../data
git clone --depth 1 https://github.com/diegoocampoh/MachineLearningPhishing     # Nazario phishing + Enron mbox
git clone --depth 1 https://github.com/rf-peixoto/phishing_pot                 # recent real phishing .eml
git clone --depth 1 https://github.com/MWiechmann/enron_spam_data && unzip -o -q enron_spam_data/enron_spam_data.zip -d enron_spam_data
git clone --depth 1 --filter=blob:none --sparse https://github.com/apache/spamassassin sa && (cd sa && git sparse-checkout set t/data/nice)
echo "done - now run: python build_dataset.py --data ../data && python train.py"
