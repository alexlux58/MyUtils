# Contacts OCR Tool

This folder contains the enhanced contacts OCR script and related files for extracting contact information from images.

## Files

- `contacts_ocr_to_csv.py` - Enhanced OCR script with improved image preprocessing
- `20250928_182846996_iOS.jpg` - Source image for OCR processing
- `contacts.csv` - Original OCR output
- `contacts_debug.csv` - Debug output with intermediate files
- `contacts_enhanced.csv` - Enhanced preprocessing output
- `contacts_final.csv` - Final output using advanced preprocessing (best results)

## Usage

```bash
# Basic usage
python3 contacts_ocr_to_csv.py --images ./20250928_182846996_iOS.jpg --out contacts.csv

# With debug output
python3 contacts_ocr_to_csv.py --images ./20250928_182846996_iOS.jpg --out contacts.csv --debug

# Process multiple images
python3 contacts_ocr_to_csv.py --images ./image1.jpg ./image2.jpg --out combined_contacts.csv
```

## Features

- **Enhanced Image Preprocessing**: Uses OpenCV for advanced image enhancement
- **Multiple OCR Configurations**: Tries different OCR settings for best results
- **Smart Fallbacks**: Falls back to simpler preprocessing if advanced methods fail
- **Confidence Scoring**: Selects the OCR configuration with highest confidence
- **Debug Mode**: Saves intermediate processing files for analysis

## Dependencies

- Python 3.7+
- OpenCV (`pip install opencv-python`)
- PIL/Pillow
- pandas
- numpy
- pytesseract

## Image Enhancement Techniques

1. **Bilateral Filtering**: Reduces noise while preserving edges
2. **CLAHE**: Contrast Limited Adaptive Histogram Equalization
3. **Otsu's Thresholding**: Automatic threshold selection for text separation
4. **Morphological Operations**: Clean up the image
5. **High-Resolution Upscaling**: 2.5x-3x upscaling for better OCR
6. **Aggressive Contrast/Sharpness Enhancement**: Improves text clarity
