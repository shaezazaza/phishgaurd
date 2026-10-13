"""ML text model: TF-IDF words + social-engineering cue counts -> Logistic Regression."""

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from .features import CUE_NAMES, clean_text, text_cues


class TextModel:
    # leftovers of URLs / forwarded headers that only tell us the *source* of an email
    JUNK = ["http", "https", "www", "com", "net", "org", "html", "htm", "cc", "bcc", "subject", "re", "fw",
            "fwd", "pm", "am", "th", "nd", "rd", "st", "to", "from", "sent", "forwarded", "original", "message"]

    def __init__(self, C=4.0, max_features=60000, classifier=None, extra_stop=None):
        stop = sorted(set(self.JUNK) | set(extra_stop or []))
        self.tfidf = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_df=0.6, max_features=max_features,
                                     sublinear_tf=True, token_pattern=r"(?u)\b[a-z][a-z']+\b",
                                     stop_words=stop)
        self.clf = classifier or LogisticRegression(C=C, max_iter=3000, class_weight="balanced")
        self.cue_weight = 0.5  # scale cue counts so they don't swamp tf-idf

    # helpers --------------------------------------------------------------
    @staticmethod
    def clean_many(subjects, bodies):
        return [clean_text(s, b) for s, b in zip(subjects, bodies)]

    def _cues(self, cleaned):
        m = np.array([[text_cues(c)[k] for k in CUE_NAMES] for c in cleaned], float)
        return csr_matrix(np.log1p(m) * self.cue_weight)

    def _X(self, cleaned, fit=False):
        T = self.tfidf.fit_transform(cleaned) if fit else self.tfidf.transform(cleaned)
        return hstack([T, self._cues(cleaned)]).tocsr()

    # api ------------------------------------------------------------------
    def fit(self, subjects, bodies, y):
        cleaned = self.clean_many(subjects, bodies)
        self.clf.fit(self._X(cleaned, fit=True), y)
        return self

    def predict_proba(self, subjects, bodies):
        X = self._X(self.clean_many(subjects, bodies))
        if hasattr(self.clf, "predict_proba"):
            return self.clf.predict_proba(X)[:, 1]
        d = self.clf.decision_function(X)
        return 1 / (1 + np.exp(-d))

    def feature_names(self):
        return list(self.tfidf.get_feature_names_out()) + CUE_NAMES

    def explain(self, subject, body, k=6):
        """Top words/cues pushing towards phishing for one email."""
        X = self._X([clean_text(subject, body)])
        coef = self.clf.coef_[0]
        contrib = X.multiply(coef).toarray()[0]
        names = self.feature_names()
        idx = np.argsort(contrib)[::-1][:k]
        return [(names[i], round(float(contrib[i]), 3)) for i in idx if contrib[i] > 0]

    def top_features(self, k=25):
        coef = self.clf.coef_[0]
        names = np.array(self.feature_names())
        o = np.argsort(coef)
        return list(zip(names[o[::-1][:k]], coef[o[::-1][:k]].round(2))), list(zip(names[o[:k]], coef[o[:k]].round(2)))
