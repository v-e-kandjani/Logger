package ransomware

import "math"

// CalculateShannonEntropy computes the Shannon entropy in bits per byte (range: 0.0 to 8.0)
// High entropy (> 7.5) indicates encrypted ciphertext or packed payloads typical of ransomware.
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	total := float64(len(data))
	entropy := 0.0

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}
