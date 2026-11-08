
from typing import Callable, Any

try:
    import albumentations as A
    from albumentations.pytorch import ToTensorV2
    HAS_ALBUMENTATIONS = True
except ImportError:
    HAS_ALBUMENTATIONS = False
    A = None
    ToTensorV2 = None


def get_augmentation(is_train: bool = True, mode: str = 'detection') -> Callable:
    if not HAS_ALBUMENTATIONS:
        # Fallback identity/resize function when albumentations is not installed
        def fallback_transform(img, **kwargs):
            return img
        return fallback_transform

    if mode == 'detection':
        transform = A.Compose([
            A.HorizontalFlip(p=0.5),
            A.RandomBrightnessContrast(p=0.3),
            A.GaussNoise(p=0.2),
            A.Blur(blur_limit=3, p=0.1),  # Privacy blur
            A.Resize(640, 640),
            ToTensorV2()
        ], bbox_params=A.BboxParams(format='yolo', label_fields=['class_labels']))
    elif mode == 'pose':
        transform = A.Compose([
            A.HorizontalFlip(p=0.5),
            A.RandomBrightnessContrast(p=0.3),
            A.GaussNoise(p=0.2),
            A.KeypointParams(keypoint_params=A.KeypointParams(format='xy')),
            A.Resize(640, 640),
            ToTensorV2()
        ])
    else:  # behavior
        transform = A.Compose([
            A.HorizontalFlip(p=0.5),
            A.RandomBrightnessContrast(p=0.3),
            ToTensorV2()
        ])
    if not is_train:
        transform = A.Compose([A.Resize(640, 640), ToTensorV2()])
    return transform