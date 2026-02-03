"""
Data Exploration & Analysis
Analyze the ISCX and CSIC datasets to understand structure and attack types.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 6)


class DataExplorer:
    """Explores and analyzes WAF datasets."""
    
    def __init__(self, data_dir: str = "Datasets"):
        self.data_dir = Path(data_dir)
        self.iscx_df = None
        self.csic_df = None
    
    def load_iscx_dataset(self) -> pd.DataFrame:
        """Load ISCX Web Attacks dataset."""
        logger.info("Loading ISCX Web Attacks dataset...")
        
        try:
            csv_path = self.data_dir / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
            
            # Read CSV with appropriate settings
            df = pd.read_csv(csv_path, encoding='utf-8', low_memory=False)
            
            logger.info(f"Loaded ISCX dataset: {df.shape}")
            self.iscx_df = df
            return df
            
        except Exception as e:
            logger.error(f"Error loading ISCX dataset: {e}")
            return None
    
    def load_csic_dataset(self) -> pd.DataFrame:
        """Load CSIC HTTP dataset."""
        logger.info("Loading CSIC HTTP dataset...")
        
        try:
            csv_path = self.data_dir / "csic_database.csv"
            
            # Read CSV
            df = pd.read_csv(csv_path, encoding='utf-8', low_memory=False)
            
            logger.info(f"Loaded CSIC dataset: {df.shape}")
            self.csic_df = df
            return df
            
        except Exception as e:
            logger.error(f"Error loading CSIC dataset: {e}")
            return None
    
    def explore_iscx(self):
        """Explore ISCX dataset structure and content."""
        if self.iscx_df is None:
            self.load_iscx_dataset()
        
        df = self.iscx_df
        
        print("\n" + "="*80)
        print("ISCX DATASET EXPLORATION")
        print("="*80)
        
        print("\n1. DATASET SHAPE & INFO")
        print(f"   Rows: {df.shape[0]}, Columns: {df.shape[1]}")
        print(f"\n   Column Names & Types:")
        print(df.dtypes)
        
        print(f"\n2. MISSING VALUES")
        missing = df.isnull().sum()
        if missing.sum() > 0:
            print(missing[missing > 0])
        else:
            print("   No missing values!")
        
        print(f"\n3. LABEL DISTRIBUTION (if exists)")
        # Look for label columns
        label_cols = [col for col in df.columns if 'label' in col.lower() or 'class' in col.lower() or 'attack' in col.lower()]
        if label_cols:
            for col in label_cols:
                print(f"\n   Column: {col}")
                print(df[col].value_counts())
        
        print(f"\n4. SAMPLE DATA")
        print(df.head())
        
        print(f"\n5. BASIC STATISTICS")
        print(df.describe())
        
        return df
    
    def explore_csic(self):
        """Explore CSIC dataset structure and content."""
        if self.csic_df is None:
            self.load_csic_dataset()
        
        df = self.csic_df
        
        print("\n" + "="*80)
        print("CSIC DATASET EXPLORATION")
        print("="*80)
        
        print("\n1. DATASET SHAPE & INFO")
        print(f"   Rows: {df.shape[0]}, Columns: {df.shape[1]}")
        print(f"\n   Column Names:")
        for i, col in enumerate(df.columns):
            print(f"   {i}: {col}")
        
        print(f"\n2. MISSING VALUES")
        missing = df.isnull().sum()
        if missing.sum() > 0:
            print(missing[missing > 0])
        else:
            print("   No missing values!")
        
        print(f"\n3. LABEL DISTRIBUTION (if exists)")
        label_cols = [col for col in df.columns if 'label' in col.lower() or 'class' in col.lower() or 'attack' in col.lower()]
        if label_cols:
            for col in label_cols:
                print(f"\n   Column: {col}")
                print(df[col].value_counts())
        else:
            print("   Checking first few columns for potential labels...")
            print(df.iloc[:, -5:].head(10))
        
        print(f"\n4. SAMPLE DATA")
        print(df.head())
        
        print(f"\n5. DATA SAMPLE - Full First Row")
        for col in df.columns:
            print(f"   {col}: {df.iloc[0][col]}")
        
        return df
    
    def analyze_csic_structure(self):
        """Detailed analysis of CSIC structure."""
        if self.csic_df is None:
            self.load_csic_dataset()
        
        df = self.csic_df
        
        print("\n" + "="*80)
        print("CSIC DETAILED STRUCTURE ANALYSIS")
        print("="*80)
        
        # Check if data contains HTTP requests
        if 'Requests' in df.columns or 'Request' in df.columns:
            print("\nFound HTTP Request column!")
            for i, req in enumerate(df.iloc[:3][df.columns[0]]):
                print(f"\nSample Request {i}:")
                print(req[:200] if isinstance(req, str) else req)
        
        # Try to identify potential label column
        print("\nPotential Label Columns:")
        for col in df.columns:
            unique_vals = df[col].nunique()
            if unique_vals <= 10:  # Likely categorical
                print(f"\n  {col}: {unique_vals} unique values")
                print(f"    Values: {df[col].unique()[:5]}")
    
    def get_dataset_summary(self):
        """Get summary of both datasets."""
        print("\n" + "="*80)
        print("DATASET SUMMARY")
        print("="*80)
        
        print("\n1. ISCX DATASET")
        if self.iscx_df is not None:
            print(f"   Shape: {self.iscx_df.shape}")
            print(f"   Size: {self.iscx_df.memory_usage().sum() / 1024**2:.2f} MB")
        else:
            print("   Not loaded")
        
        print("\n2. CSIC DATASET")
        if self.csic_df is not None:
            print(f"   Shape: {self.csic_df.shape}")
            print(f"   Size: {self.csic_df.memory_usage().sum() / 1024**2:.2f} MB")
        else:
            print("   Not loaded")


def main():
    """Run data exploration."""
    explorer = DataExplorer()
    
    # Explore ISCX
    iscx_df = explorer.explore_iscx()
    
    # Explore CSIC
    csic_df = explorer.explore_csic()
    
    # Detailed CSIC analysis
    explorer.analyze_csic_structure()
    
    # Summary
    explorer.get_dataset_summary()
    
    # Save exploration report
    print("\n" + "="*80)
    print("DATA EXPLORATION COMPLETE")
    print("="*80)
    print("\nNext Steps:")
    print("1. Identify attack labels in each dataset")
    print("2. Extract HTTP features from request payloads")
    print("3. Create balanced training/test sets")
    print("4. Train ML models")


if __name__ == "__main__":
    main()