"""Small CPU autoencoder: scaler and weights fit only benign training rows."""

import numpy as np
import torch
from sklearn.preprocessing import StandardScaler

from src.detect.features import matrix


class Autoencoder:
    def __init__(self, seed=42, hidden=8, epochs=10, threads=2, quantile=0.99):
        torch.manual_seed(seed)
        torch.set_num_threads(threads)
        self.model = torch.nn.Sequential(
            torch.nn.Linear(6, hidden), torch.nn.ReLU(), torch.nn.Linear(hidden, 6)
        )
        self.scaler = StandardScaler()
        self.epochs = epochs
        self.quantile = quantile
        self.threshold = None

    def fit(self, train, validation):
        benign = train[train.label == 0]
        clean_validation = validation[validation.label == 0]
        if benign.empty or clean_validation.empty:
            raise ValueError("benign training and validation required")
        x = torch.tensor(self.scaler.fit_transform(matrix(benign)), dtype=torch.float32)
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        self.model.train()
        for _ in range(self.epochs):
            for batch in x.split(128):
                optimizer.zero_grad()
                loss = ((self.model(batch) - batch) ** 2).mean()
                loss.backward()
                optimizer.step()
        self.threshold = float(np.quantile(self.errors(clean_validation), self.quantile))
        return self

    def errors(self, frame):
        self.model.eval()
        with torch.no_grad():
            x = torch.tensor(self.scaler.transform(matrix(frame)), dtype=torch.float32)
            return ((self.model(x) - x) ** 2).mean(dim=1).numpy()

    def predict(self, frame):
        if self.threshold is None:
            raise RuntimeError("not fitted")
        # Bounded anomaly score; not a calibrated attack probability.
        return 1 - np.exp(-self.errors(frame) / max(self.threshold, 1e-9))

    def save(self, path):
        torch.save(
            {
                "weights": self.model.state_dict(),
                "mean": self.scaler.mean_.tolist(),
                "scale": self.scaler.scale_.tolist(),
                "threshold": self.threshold,
            },
            path,
        )

    def restore(self, path):
        state = torch.load(path, map_location="cpu", weights_only=True)
        self.model.load_state_dict(state["weights"])
        self.scaler.mean_ = np.asarray(state["mean"])
        self.scaler.scale_ = np.asarray(state["scale"])
        self.scaler.var_ = self.scaler.scale_**2
        self.scaler.n_features_in_ = 6
        self.threshold = state["threshold"]
        return self
