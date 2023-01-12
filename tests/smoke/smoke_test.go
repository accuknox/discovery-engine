package smoke_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Smoke", func() {
	It("adds two numbers", func() {
		sum := 2 + 3
		Expect(sum).To(Equal(5))
	})
})
