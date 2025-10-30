// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Poseidon2Lib} from "@poseidon2/src/Poseidon2Lib.sol";
import {Field} from "@poseidon2/src/Field.sol";

/**
 * @notice Merkle Mountain Range with Poseidon2 hashing.
 * @dev Indexing starts at 1 (not 0)
 */
library MMRPoseidon2 {
    struct Tree {
        bytes32 root; // Poseidon2 root commitment
        uint256 size; // total number of nodes in the implicit forest
        uint256 width; // number of leaves appended so far
        mapping(uint256 => bytes32) hashes; // nodeIndex => nodeHash
    }

    // ========= PUBLIC / EXTERNAL-FACING LOGIC =========

    /**
     * @notice Append a new leaf.
     * @dev dataHash is any bytes32 you consider "leaf payload hash".
     *      We mod it into the Poseidon field to keep consistency.
     *
     * Effects:
     *  - updates width, size, root
     *  - writes new leaf hash and any internal branch hashes
     */
    function append(Tree storage tree, bytes32 dataHash) public returns (uint256 newLeafIndex) {
        // fit into Poseidon2 field
        bytes32 dataHashMod = _fieldMod(dataHash);

        // increment logical width (#leaves)
        tree.width += 1;

        // compute the leaf index for this new leaf in the "mountain range index space"
        newLeafIndex = getLeafIndex(tree.width);

        // hash leaf node as Poseidon2(index || value)
        bytes32 leafNode = _hashLeaf(newLeafIndex, dataHashMod);

        // store leaf in node map
        tree.hashes[newLeafIndex] = leafNode;

        // figure out peak indexes (the tops of each "mountain")
        uint256[] memory peakIndexes = _getPeakIndexes(tree.width);

        // update size to rightmost peak index
        tree.size = _calcSize(tree.width);

        // walk each peak top → recursively fill internal hashes if missing
        bytes32[] memory peaks = new bytes32[](peakIndexes.length);
        for (uint256 i = 0; i < peakIndexes.length; i++) {
            peaks[i] = _getOrCreateNode(tree, peakIndexes[i]);
        }

        // recompute MMR root as "peak bagging" of all current peaks
        tree.root = _peakBagging(tree.width, peaks);
    }

    /**
     * @notice Return current root.
     */
    function getRoot(Tree storage tree) internal view returns (bytes32) {
        return tree.root;
    }

    /**
     * @notice Return current width (#leaves).
     */
    function getWidth(Tree storage tree) public view returns (uint256) {
        return tree.width;
    }

    /**
     * @notice Return current size (MMR node space upper bound).
     */
    function getSize(Tree storage tree) internal view returns (uint256) {
        return tree.size;
    }

    /**
     * @notice Get stored node hash at an absolute node index (1-based).
     */
    function getNodeHash(Tree storage tree, uint256 index) internal view returns (bytes32) {
        return tree.hashes[index];
    }

    /**
     * @notice Return all peak hashes (same order as in peak bagging).
     */
    function getPeaks(Tree storage tree) internal view returns (bytes32[] memory peaks) {
        uint256[] memory peakNodeIndexes = _getPeakIndexes(tree.width);
        peaks = new bytes32[](peakNodeIndexes.length);
        for (uint256 i = 0; i < peakNodeIndexes.length; i++) {
            peaks[i] = tree.hashes[peakNodeIndexes[i]];
        }
    }

    /**
     * @notice Compute the leaf index for the given width.
     * @dev Width is 1-indexed count of leaves; leaf index is 1-indexed MMR node index.
     */
    function getLeafIndex(uint256 width_) internal pure returns (uint256) {
        // same 1-indexed indexing logic
        if (width_ % 2 == 1) {
            return _calcSize(width_);
        } else {
            return _calcSize(width_ - 1) + 1;
        }
    }

    /**
     * @notice Build Merkle inclusion proof for a specific leaf index.
     * @dev Reverts if index is not a leaf or out of range.
     *
     * Returns:
     *  - root: current root
     *  - width: current width (#leaves)
     *  - peakBag: array of peak hashes used in peak bagging
     *  - siblings: sibling path from leaf → peak
     */
    function getMerkleProof(Tree storage tree, uint256 index)
        public
        view
        returns (bytes32 root_, uint256 width_, bytes32[] memory peakBag, bytes32[] memory siblings)
    {
        require(index <= tree.size, "MMR:OutOfRange");
        require(_isLeaf(index), "MMR:NotLeaf");

        root_ = tree.root;
        width_ = tree.width;

        // gather peaks + locate which peak covers this index
        uint256[] memory peakIdxs = _getPeakIndexes(tree.width);
        peakBag = new bytes32[](peakIdxs.length);

        uint256 cursor = 0;
        for (uint256 i = 0; i < peakIdxs.length; i++) {
            peakBag[i] = tree.hashes[peakIdxs[i]];
            if (peakIdxs[i] >= index && cursor == 0) {
                cursor = peakIdxs[i];
            }
        }
        require(cursor != 0, "MMR:PeakNotFound");

        // descend from that peak down to the index, recording siblings
        uint8 h = _heightAt(cursor);
        siblings = new bytes32[](h - 1);

        while (cursor != index) {
            h--;
            (uint256 left, uint256 right) = _getChildren(cursor);
            // go down
            cursor = index <= left ? left : right;
            // record sibling
            siblings[h - 1] = tree.hashes[index <= left ? right : left];
        }
    }

    /**
     * @notice Check proof on-chain (stateless verifier).
     * @dev Matches inclusionProof logic in your previous version.
     */
    function verifyInclusion(
        bytes32 root_,
        uint256 width_,
        uint256 index,
        bytes32 valueHash,
        bytes32[] calldata peakBag,
        bytes32[] calldata siblings
    ) public pure returns (bool) {
        require(_calcSize(width_) >= index, "MMR:IndexOOB");

        // root must equal bagged peak hash
        require(root_ == _peakBagging(width_, peakBag), "MMR:BadRoot");

        // find target peak + starting cursor
        bytes32 targetPeak;
        uint256 cursor;
        {
            uint256[] memory peakIdxs = _getPeakIndexes(width_);
            for (uint256 i = 0; i < peakIdxs.length; i++) {
                if (peakIdxs[i] >= index) {
                    targetPeak = peakBag[i];
                    cursor = peakIdxs[i];
                    break;
                }
            }
        }
        require(targetPeak != bytes32(0), "MMR:NoPeakForIndex");

        // walk DOWN from peak to the index, record path
        uint256[] memory path = new uint256[](siblings.length + 1);
        uint8 h = uint8(siblings.length) + 1;
        while (h > 0) {
            path[--h] = cursor;
            if (cursor == index) break;
            (uint256 l, uint256 r) = _getChildren(cursor);
            cursor = index > l ? r : l;
        }

        // now walk UP recomputing hashes
        bytes32 node;
        while (h < path.length) {
            cursor = path[h];
            if (h == 0) {
                // leaf
                node = _hashLeaf(cursor, valueHash);
            } else if (cursor - 1 == path[h - 1]) {
                // sibling is on the left
                node = _hashBranch(cursor, siblings[h - 1], node);
            } else {
                // sibling is on the right
                node = _hashBranch(cursor, node, siblings[h - 1]);
            }
            h++;
        }

        require(node == targetPeak, "MMR:BadPeakHash");
        return true;
    }

    // ========= INTERNAL / PURE HELPERS =========

    function _calcSize(uint256 width_) internal pure returns (uint256) {
        // (width << 1) - popcount(width)
        return (width_ << 1) - _numOfPeaks(width_);
    }

    function _hashBranch(uint256 index, bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return Field.toBytes32(Poseidon2Lib.hash_3(Field.toField(index), Field.toField(left), Field.toField(right)));
    }

    function _hashLeaf(uint256 index, bytes32 dataHash) internal pure returns (bytes32) {
        return Field.toBytes32(Poseidon2Lib.hash_2(Field.toField(index), Field.toField(dataHash)));
    }

    function _fieldMod(bytes32 dataHash) internal pure returns (bytes32) {
        // reduce into BN256 scalar field to align with Poseidon2 field
        return bytes32(uint256(dataHash) % Field.PRIME);
    }

    function _peakBagging(uint256 width_, bytes32[] memory peaks_) internal pure returns (bytes32) {
        if (width_ == 0) return bytes32(0);

        uint256 size_ = _calcSize(width_);
        require(_numOfPeaks(width_) == peaks_.length, "MMR:BadPeakCount");

        // fold: acc = H(acc, peak[i])
        Field.Type acc = Field.toField(size_);
        for (uint256 i = 0; i < peaks_.length; i++) {
            acc = Poseidon2Lib.hash_2(acc, Field.toField(peaks_[i]));
        }

        // final bind again with size
        return Field.toBytes32(Poseidon2Lib.hash_2(Field.toField(size_), Field.toField(Field.toBytes32(acc))));
    }

    function _getPeakIndexes(uint256 width_) internal pure returns (uint256[] memory peakIndexes) {
        uint256 numPeaks = _numOfPeaks(width_);
        peakIndexes = new uint256[](numPeaks);

        // compute maxHeight (same as your version)
        uint8 maxHeight = 1;
        while ((1 << maxHeight) <= width_) {
            maxHeight++;
        }

        uint256 count;
        uint256 runningSize;
        for (uint256 i = maxHeight; i > 0; i--) {
            if (width_ & (1 << (i - 1)) != 0) {
                runningSize = runningSize + (1 << i) - 1;
                peakIndexes[count++] = runningSize;
            }
        }

        require(count == numPeaks, "MMR:PeakCalcMismatch");
    }

    function _heightAt(uint256 index) internal pure returns (uint8 height) {
        uint256 reducedIndex = index;
        uint256 peakIndex;
        while (reducedIndex > peakIndex) {
            reducedIndex -= (uint256(1) << height) - 1;
            height = _mountainHeight(reducedIndex);
            peakIndex = (uint256(1) << height) - 1;
        }
        height = height - uint8((peakIndex - reducedIndex));
    }

    function _isLeaf(uint256 index) internal pure returns (bool) {
        return _heightAt(index) == 1;
    }

    function _getChildren(uint256 index) internal pure returns (uint256 left, uint256 right) {
        left = index - (uint256(1) << (_heightAt(index) - 1));
        right = index - 1;
        require(left != right, "MMR:NotParent");
    }

    function _mountainHeight(uint256 size_) internal pure returns (uint8) {
        uint8 height = 1;
        while (uint256(1) << height <= size_ + height) {
            height++;
        }
        return height - 1;
    }

    function _numOfPeaks(uint256 width_) internal pure returns (uint256 num) {
        uint256 bits = width_;
        while (bits > 0) {
            num++;
            bits = bits & (bits - 1); // pop low set bit
        }
    }

    // NOTE: _getOrCreateNode is the only mutating helper left outside append()
    function _getOrCreateNode(Tree storage tree, uint256 index) private returns (bytes32) {
        require(index <= tree.size, "MMR:OOBNode");
        bytes32 cached = tree.hashes[index];
        if (cached != bytes32(0)) return cached;

        (uint256 leftIdx, uint256 rightIdx) = _getChildren(index);
        bytes32 leftHash = _getOrCreateNode(tree, leftIdx);
        bytes32 rightHash = _getOrCreateNode(tree, rightIdx);

        bytes32 branch = _hashBranch(index, leftHash, rightHash);
        tree.hashes[index] = branch;
        return branch;
    }
}
