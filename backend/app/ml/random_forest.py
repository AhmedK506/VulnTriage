"""
Pure numpy Random Forest Classifier

Implements a Random Forest from scratch using only numpy and Python stdlib.
No scikit-learn required — avoids Windows AppControl DLL restrictions while
demonstrating full algorithmic understanding for the FYP.

Algorithm:
  1. Bootstrap sample the training data B times
  2. For each bootstrap: grow a decision tree using sqrt(n_features) random
     features at each split, GINI impurity criterion
  3. Predict by majority vote across all trees
  4. Persist with pickle (stdlib, no compiled DLLs needed)
"""

import pickle
import numpy as np
from collections import Counter


# ------------------------------------------------------------------ #
#  GINI impurity                                                       #
# ------------------------------------------------------------------ #

def _gini(y: np.ndarray) -> float:
    if len(y) == 0:
        return 0.0
    counts = np.bincount(y)
    probs = counts / len(y)
    return float(1.0 - np.sum(probs ** 2))


def _weighted_gini(y_left: np.ndarray, y_right: np.ndarray) -> float:
    n = len(y_left) + len(y_right)
    if n == 0:
        return 0.0
    return (len(y_left) / n) * _gini(y_left) + (len(y_right) / n) * _gini(y_right)


# ------------------------------------------------------------------ #
#  Decision Tree Node                                                  #
# ------------------------------------------------------------------ #

class _Node:
    __slots__ = ("feature", "threshold", "left", "right", "value", "proba")

    def __init__(self):
        self.feature = None
        self.threshold = None
        self.left = None
        self.right = None
        self.value = None    # leaf: predicted class index
        self.proba = None    # leaf: class probability array


class _DecisionTree:
    def __init__(
        self,
        max_depth: int = 15,
        min_samples_split: int = 5,
        min_samples_leaf: int = 2,
        max_features: int | None = None,
        n_classes: int = 4,
        rng: np.random.Generator = None,
    ):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.max_features = max_features
        self.n_classes = n_classes
        self.rng = rng or np.random.default_rng()
        self.root: _Node | None = None

    def fit(self, X: np.ndarray, y: np.ndarray, sample_weight=None) -> None:
        self.root = self._grow(X, y, depth=0)

    def _grow(self, X: np.ndarray, y: np.ndarray, depth: int) -> _Node:
        node = _Node()

        # Leaf conditions
        if (
            depth >= self.max_depth
            or len(y) < self.min_samples_split
            or len(np.unique(y)) == 1
        ):
            node.value, node.proba = self._leaf_value(y)
            return node

        # Select random feature subset
        n_features = X.shape[1]
        k = self.max_features or max(1, int(np.sqrt(n_features)))
        feature_indices = self.rng.choice(n_features, size=min(k, n_features), replace=False)

        best_gini = float("inf")
        best_feat = None
        best_thresh = None

        for fi in feature_indices:
            col = X[:, fi]
            # Use unique midpoints as candidate thresholds
            unique_vals = np.unique(col)
            if len(unique_vals) == 1:
                continue
            thresholds = (unique_vals[:-1] + unique_vals[1:]) / 2.0

            for thresh in thresholds:
                mask = col <= thresh
                y_left, y_right = y[mask], y[~mask]
                if len(y_left) < self.min_samples_leaf or len(y_right) < self.min_samples_leaf:
                    continue
                g = _weighted_gini(y_left, y_right)
                if g < best_gini:
                    best_gini = g
                    best_feat = fi
                    best_thresh = thresh

        if best_feat is None:
            node.value, node.proba = self._leaf_value(y)
            return node

        node.feature = best_feat
        node.threshold = best_thresh
        mask = X[:, best_feat] <= best_thresh
        node.left = self._grow(X[mask], y[mask], depth + 1)
        node.right = self._grow(X[~mask], y[~mask], depth + 1)
        return node

    def _leaf_value(self, y: np.ndarray):
        counts = np.bincount(y, minlength=self.n_classes)
        proba = counts / counts.sum()
        return int(counts.argmax()), proba

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.array([self._traverse(x, self.root) for x in X])

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return np.array([self._traverse_proba(x, self.root) for x in X])

    def _traverse(self, x: np.ndarray, node: _Node) -> int:
        if node.value is not None:
            return node.value
        if x[node.feature] <= node.threshold:
            return self._traverse(x, node.left)
        return self._traverse(x, node.right)

    def _traverse_proba(self, x: np.ndarray, node: _Node) -> np.ndarray:
        if node.proba is not None:
            return node.proba
        if x[node.feature] <= node.threshold:
            return self._traverse_proba(x, node.left)
        return self._traverse_proba(x, node.right)


# ------------------------------------------------------------------ #
#  Random Forest                                                       #
# ------------------------------------------------------------------ #

class NumpyRandomForest:
    """
    Random Forest Classifier using only numpy + stdlib.
    API mirrors scikit-learn's RandomForestClassifier.
    """

    def __init__(
        self,
        n_estimators: int = 200,
        max_depth: int = 15,
        min_samples_split: int = 5,
        min_samples_leaf: int = 2,
        max_features: str | int | None = "sqrt",
        random_state: int = 42,
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.min_samples_leaf = min_samples_leaf
        self.max_features = max_features
        self.random_state = random_state
        self.trees_: list[_DecisionTree] = []
        self.classes_: np.ndarray | None = None
        self.n_classes_: int = 0
        self.feature_importances_: np.ndarray | None = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> "NumpyRandomForest":
        rng = np.random.default_rng(self.random_state)
        self.classes_ = np.sort(np.unique(y))
        self.n_classes_ = len(self.classes_)

        # Map labels to 0..n_classes-1
        label_map = {c: i for i, c in enumerate(self.classes_)}
        y_enc = np.array([label_map[c] for c in y])

        n_samples, n_features = X.shape
        k = self._resolve_max_features(n_features)

        self.trees_ = []
        oob_preds = np.zeros((n_samples, self.n_classes_))
        oob_counts = np.zeros(n_samples, dtype=int)

        for i in range(self.n_estimators):
            seed = int(rng.integers(0, 2**31))
            tree_rng = np.random.default_rng(seed)

            # Bootstrap sample
            idx = tree_rng.choice(n_samples, size=n_samples, replace=True)
            oob_idx = np.setdiff1d(np.arange(n_samples), idx)

            tree = _DecisionTree(
                max_depth=self.max_depth,
                min_samples_split=self.min_samples_split,
                min_samples_leaf=self.min_samples_leaf,
                max_features=k,
                n_classes=self.n_classes_,
                rng=tree_rng,
            )
            tree.fit(X[idx], y_enc[idx])
            self.trees_.append(tree)

            # OOB predictions for feature importance proxy
            if len(oob_idx) > 0:
                oob_preds[oob_idx] += tree.predict_proba(X[oob_idx])
                oob_counts[oob_idx] += 1

            if (i + 1) % 20 == 0:
                print(f"  [RF] {i+1}/{self.n_estimators} trees trained", flush=True)

        # Compute feature importances via permutation-style approximation
        self.feature_importances_ = self._compute_importances(X, y_enc)
        return self

    def _resolve_max_features(self, n_features: int) -> int:
        if self.max_features == "sqrt":
            return max(1, int(np.sqrt(n_features)))
        if self.max_features == "log2":
            return max(1, int(np.log2(n_features)))
        if isinstance(self.max_features, int):
            return min(self.max_features, n_features)
        return max(1, int(np.sqrt(n_features)))

    def _compute_importances(self, X: np.ndarray, y: np.ndarray) -> np.ndarray:
        """
        Mean decrease in node impurity across all trees and features.
        Approximated by counting how many times each feature is used
        as a split, weighted by the sample fraction at that node.
        """
        importances = np.zeros(X.shape[1])
        for tree in self.trees_:
            self._traverse_importances(tree.root, importances, len(y))
        total = importances.sum()
        return importances / total if total > 0 else importances

    def _traverse_importances(self, node: _Node, imp: np.ndarray, n_total: int):
        if node is None or node.value is not None:
            return
        if node.feature is not None:
            imp[node.feature] += 1.0
        self._traverse_importances(node.left, imp, n_total)
        self._traverse_importances(node.right, imp, n_total)

    def predict(self, X: np.ndarray) -> np.ndarray:
        # Aggregate predictions across all trees (majority vote)
        all_preds = np.array([tree.predict(X) for tree in self.trees_])
        # Mode across rows
        votes = np.apply_along_axis(
            lambda col: np.bincount(col, minlength=self.n_classes_).argmax(),
            axis=0,
            arr=all_preds,
        )
        return self.classes_[votes]

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        all_proba = np.array([tree.predict_proba(X) for tree in self.trees_])
        return all_proba.mean(axis=0)

    def save(self, path: str) -> None:
        with open(path, "wb") as f:
            pickle.dump(self, f, protocol=pickle.HIGHEST_PROTOCOL)

    @staticmethod
    def load(path: str) -> "NumpyRandomForest":
        with open(path, "rb") as f:
            return pickle.load(f)
