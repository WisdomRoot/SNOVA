# SNOVA

This repository contains the latest official C implementations of the SNOVA signature scheme, including the Reference, Optimized, and AVX2 implementations.

1. The `src` directory contains the SNOVA v3.1 implementation.
2. The `dist` directory contains a Makefile for building all recommended SNOVA parameter instances, with each instance generated in a separate subdirectory.
3. The `sage` directory contains a SageMath implementation of SNOVA, together with additional SageMath scripts.
4. The `liboqs` directory contains the files required for integration with [liboqs](https://github.com/open-quantum-safe/liboqs).

For additional information, please refer to the README files in the respective subdirectories.

## AI Disclosure

The AVX2 implementation is derived from the Optimized implementation and was further optimized with the assistance of Claude Code.

ChatGPT and Claude Opus were used for language editing and refinement of the Supporting Document and README files. All AI-assisted contributions were reviewed by the authors. The authors retain full responsibility for the technical content, implementation, correctness, and final wording of the submitted materials.
