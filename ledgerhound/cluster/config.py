"""Clustering configuration: relation weights and campaign thresholds,
loaded from config/clustering.yaml. All defaults match the milestone
spec; the file just makes them tunable without a code change, same
pattern as `enrich/registry.py`'s `config/providers.yaml`.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class RelationWeights(BaseModel):
    shares_receiving_wallet: float = 1.0
    shares_cashout_path: float = 0.8
    shares_cert: float = 0.6
    shares_template: float = 0.5
    shares_registrar_and_ns: float = 0.2


class CertConfig(BaseModel):
    wildcard_san_threshold: int = Field(default=20, gt=0)
    wildcard_weight: float = Field(default=0.1, ge=0)
    liveness_window_days: int = Field(default=90, gt=0)


class TemplateConfig(BaseModel):
    liveness_window_days: int = Field(default=90, gt=0)


class CampaignConfig(BaseModel):
    score_threshold: float = Field(default=0.5, ge=0)
    diversity_bonus: float = Field(default=0.2, ge=0)
    min_size: int = Field(default=2, ge=2)
    merge_split_jaccard_threshold: float = Field(default=0.5, gt=0, le=1)
    active_window_days: int = Field(default=30, gt=0)


class ClusteringConfig(BaseModel):
    weights: RelationWeights = Field(default_factory=RelationWeights)
    cert: CertConfig = Field(default_factory=CertConfig)
    template: TemplateConfig = Field(default_factory=TemplateConfig)
    campaign: CampaignConfig = Field(default_factory=CampaignConfig)


DEFAULT_CONFIG_PATH = Path("config/clustering.yaml")


def load_clustering_config(path: Path = DEFAULT_CONFIG_PATH) -> ClusteringConfig:
    if not path.is_file():
        return ClusteringConfig()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return ClusteringConfig.model_validate(raw)

