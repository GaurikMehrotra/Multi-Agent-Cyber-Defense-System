# Optional Kaggle GPU experiment

Check current account-specific GPU quotas and dataset terms; do not assume 30 hours/week. Sessions can terminate. Run the required small CPU workflow locally first. Upload only approved canonical flow CSVs and manifests privately, never secrets or captures. These cells are supplied for a future run; they have not run on Kaggle.

Cell 1:
```python
!git clone https://github.com/GaurikMehrotra/Multi-Agent-Cyber-Defense-System.git /kaggle/working/cyber-defense
%cd /kaggle/working/cyber-defense
!python -m pip install -r requirements.txt
```

Cell 2 (exact CPU experiment, portable validation before heavier GPU changes):
```python
!python -m src.eval.run_detection --config configs/default.yaml --output /kaggle/working/results
```

Cell 3 (restore the retained CPU checkpoint safely after session restart):
```python
from src.detect.autoencoder import Autoencoder
from src.config import load
cfg = load('configs/default.yaml')
model = Autoencoder(seed=42, hidden=int(cfg.models['ae_hidden']), epochs=int(cfg.models['ae_epochs']))
model.restore('/kaggle/working/results/ae-temporal-42.pt')
```

Cell 4:
```python
import shutil
shutil.make_archive('/kaggle/working/cyber-results', 'zip', '/kaggle/working/results')
```

Download the result archive before the session ends. Model checkpoints resume inference; current small training runs restart from a fixed seed. A heavier GPU model, resumable optimizer/epoch training and GPU evaluation are not implemented milestones and are not claimed complete. Do not change train/test splits to get higher numbers.
