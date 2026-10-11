"""CPU XGBoost on identifier-free features; explanations are model attribution, not causation."""

from xgboost import XGBClassifier

from src.detect.features import matrix


class Detector:
    def __init__(self, seed=42, estimators=40, threads=2):
        self.model = XGBClassifier(
            n_estimators=estimators,
            max_depth=3,
            n_jobs=threads,
            random_state=seed,
            eval_metric="logloss",
            tree_method="hist",
            device="cpu",
        )

    def fit(self, train):
        if train.label.nunique() != 2:
            raise ValueError("XGBoost requires both classes in training")
        self.model.fit(matrix(train), train.label)
        return self

    def predict(self, frame):
        return self.model.predict_proba(matrix(frame))[:, 1]

    def explain(self, frame):
        import shap

        return shap.TreeExplainer(self.model)(matrix(frame)).values
