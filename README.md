# PhishGuard: AI-driven phishing and social-engineering detection

PhishGuard scans an email and gives it a **risk score (0–100)**, a **level** (Low / Medium / High), an **action** (deliver, warn and review, or quarantine), and **plain-English reasons** for the score.

## How it works

```
 .eml file ─► parser ─► 1. Text model (ML)       words + social-engineering cues  ─┐
                        2. Rule layer             SPF/DKIM/DMARC, sender, links,   ├─► risk 0-100 + reasons
                                                  attachments                       │      │
                        3. Threat intel           blocklists + optional APIs      ─┘      ▼
                                                                          triage queue + campaign grouping
```

| Objective in the brief | Where it is done |
|---|---|
| 1. Classify text, headers, URLs and attachments | `textmodel.py` (text), `rules.py` + `features.py` (headers, URLs, attachments) |
| 2. Spot impersonation and urgency | cue lists in `features.py`; brand / look-alike / reply-to checks in `rules.py` |
| 3. Check threat intelligence | `intel.py`: offline phishing blocklists, plus URLhaus / Google Safe Browsing / VirusTotal if you set API keys |
| 4. Explain the risk | each score lists its reasons and their points, the social-engineering tactics found, and the key words |
| 5. Send suspicious mail to analysts | `triage.py`: a ranked queue, with similar emails grouped into one campaign |

## Quick start

```bash
pip install -r requirements.txt
python -m phishguard feeds --update                 # download phishing blocklists (~75 MB)
python -m phishguard scan suspicious.eml            # scan one email
python -m phishguard text "Account locked" "Verify your password now at http://..." --from a@b.com
python -m phishguard triage inbox_folder/ --csv queue.csv    # scan a folder, get a ranked queue
```

Optional online lookups. Set any of these environment variables to turn them on: `URLHAUS_KEY`, `GSB_KEY`, `VT_KEY`. Use `--offline` to skip online lookups.

## Retrain from scratch

```bash
./get_data.sh                          # public datasets from GitHub (~2.7 GB)
python build_dataset.py --data ../data # -> data/emails.parquet
python train.py                        # -> models/text_model.joblib + reports/metrics.json (~4 min on CPU)
python train_transformer.py            # optional, needs a GPU: DistilBERT fine-tune
```

## Data

| Source | Type | Emails used (English, de-duplicated) |
|---|---|---|
| Nazario corpus (2005–07) | phishing | 1,568 |
| phishing_pot (2022–2026, real `.eml`) | phishing | 4,152 |
| Enron mbox | legit | 3,587 |
| Enron-Spam "ham" | legit | 14,529 |

## Results (`reports/metrics.json`)

**Main test.** The test set is the newest 20% of phishing_pot plus a random 20% of the other sources. None of it was used for training.

| Model | Precision | Recall | F1 | ROC-AUC | False-alarm rate |
|---|---|---|---|---|---|
| **Logistic Regression** (shipped, easiest to explain) | 0.987 | 0.956 | 0.971 | 0.998 | 0.41% |
| Linear SVM | 0.989 | 0.962 | 0.976 | 0.999 | 0.33% |
| Naive Bayes | 0.961 | 0.919 | 0.940 | 0.995 | 1.19% |

**Era-shift test.** A model trained only on old data (2005-era phishing plus Enron) catches just **24%** of recent phishing. With recent data in training it catches 94%. Phishing changes quickly, so the model needs regular retraining.

**Full system on 60 of the newest phishing emails.** All 60 were flagged (56 High, 4 Medium). Campaign grouping turned 65 suspicious emails into 29 analyst items.

## Limits (please read)

1. **All legit training mail is Enron corporate mail from around 2000.** The scores above say little about false alarms on *modern* legit mail such as newsletters, bank alerts and college emails. To test that, run `python evaluate_folder.py --legit my_legit/ --phish my_phish/` on your own exported emails. That is the most important next test.
2. **English only.** Non-English emails were left out of training. The model has not been checked on them, and may wrongly flag Hindi or other non-English legit mail.
3. **Rule points are hand-set.** The legit training mail has no modern headers or links, so the rule weights can't be learned from it. Tune them in `rules.py` once you have labelled mail of your own.
4. **Brand words lean toward phishing.** Old phishing is full of PayPal and eBay. Real PayPal mail that passes DMARC gets its text score lowered, but unauthenticated brand mail can still land in Medium.
5. **The transformer script has only been smoke-tested** (on a tiny random model, because the model hub was blocked in the build environment). Run it on a GPU to get real numbers.
