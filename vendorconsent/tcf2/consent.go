package vendorconsent

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/prebid/go-gdpr/api"
	"github.com/prebid/go-gdpr/bitutils"
	"github.com/prebid/go-gdpr/consentconstants"
)

const (
	consentStringTCF2Separator = '.'
	consentStringTCF2Prefix    = 'C'
)

const (
	segmentTypeDisclosedVendors = 1 // Disclosed Vendors segment
	segmentTypeBitSize          = 3 // SegmentType field is 3 bits
)

type consentString struct {
	data []byte
}

func (c *consentString) NextSegment() []byte {
	if index := bytes.IndexByte(c.data, consentStringTCF2Separator); index != -1 {
		parsed := c.data[:index]
		c.data = c.data[index+1:]
		return parsed
	}
	parsed := c.data
	c.data = nil
	return parsed
}

// ParseString parses the TCF 2.0 vendor string base64 encoded
func ParseString(consent string) (api.VendorConsents, error) {
	if consent == "" {
		return nil, consentconstants.ErrEmptyDecodedConsent
	}

	buff := []byte(consent)
	c := consentString{data: buff}
	coreStr := c.NextSegment()

	writePos, err := base64.RawURLEncoding.Decode(buff, coreStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode core segment: %w", err)
	}
	coreDecoded := buff[:writePos]

	// Decode additional segments, looking for Disclosed Vendors
	disclosedOffset := 0
	disclosedEnd := 0
	for {
		nextSegment := c.NextSegment()
		if len(nextSegment) == 0 {
			break
		}

		n, err := base64.RawURLEncoding.Decode(buff[writePos:], nextSegment)
		if err != nil {
			return nil, fmt.Errorf("failed to decode segment: %w", err)
		}

		if n > 0 && (buff[writePos]>>5) == segmentTypeDisclosedVendors {
			disclosedOffset = writePos
			disclosedEnd = writePos + n
		}
		writePos += n
	}

	metadata, err := parseCore(coreDecoded)
	if err != nil {
		return nil, err
	}

	if disclosedOffset > 0 {
		metadata.disclosedVendors, err = parseVendorSection(buff[disclosedOffset:disclosedEnd], segmentTypeBitSize)
		if err != nil {
			return nil, err
		}
	}

	return metadata, nil
}

// Parse parses the TCF 2.0 vendor consent data from the bytes. This data should *not* be encoded (by base64 or any other encoding).
// If the data is malformed and cannot be interpreted as a vendor consent string, this will return an error.
// Note: This parses only the core consent data segment. Use ParseString to parse consent strings with additional segments (e.g., Disclosed Vendors).
func Parse(data []byte) (api.VendorConsents, error) {
	metadata, err := parseCore(data)
	if err != nil {
		return nil, err
	}
	return metadata, nil
}

// parseCore parses the core TCF 2.0 consent data and returns a pointer to allow modification.
func parseCore(data []byte) (*ConsentMetadata, error) {
	metadata, err := parseMetadata(data)
	if err != nil {
		return nil, err
	}

	var vendorConsents vendorConsentsResolver
	var vendorLegitInts vendorConsentsResolver

	var legitIntStart uint
	var pubRestrictsStart uint
	// Bit 229 determines whether or not the consent string encodes Vendor data in a RangeSection or BitField.
	// We know from parseMetadata that we have at least 29*8=232 bits available
	if isSet(data, 229) {
		vendorConsents, legitIntStart, err = parseRangeSection(data, metadata.MaxVendorID(), 230)
	} else {
		vendorConsents, legitIntStart, err = parseBitField(data, metadata.MaxVendorID(), 230)
	}
	if err != nil {
		return nil, err
	}

	metadata.vendorConsents = vendorConsents
	metadata.vendorLegitimateInterestStart = legitIntStart + 17
	legIntMaxVend, err := bitutils.ParseUInt16(data, legitIntStart)
	if err != nil {
		return nil, err
	}

	if legitIntStart+16 >= uint(len(data))*8 {
		return nil, fmt.Errorf("invalid consent data: no legitimate interest start position")
	}
	if isSet(data, legitIntStart+16) {
		vendorLegitInts, pubRestrictsStart, err = parseRangeSection(data, legIntMaxVend, metadata.vendorLegitimateInterestStart)
	} else {
		vendorLegitInts, pubRestrictsStart, err = parseBitField(data, legIntMaxVend, metadata.vendorLegitimateInterestStart)
	}
	if err != nil {
		return nil, err
	}

	metadata.vendorLegitimateInterests = vendorLegitInts
	metadata.pubRestrictionsStart = pubRestrictsStart

	pubRestrictions, _, err := parsePubRestriction(data, pubRestrictsStart)
	if err != nil {
		return nil, err
	}

	metadata.publisherRestrictions = pubRestrictions

	return &metadata, nil
}

// parseVendorSection parses a vendor section (used for Disclosed Vendors segment).
// startBit should point to the MaxVendorId field (after any segment header).
func parseVendorSection(data []byte, startBit uint) (vendorConsentsResolver, error) {
	maxVendorID, err := bitutils.ParseUInt16(data, startBit)
	if err != nil {
		return nil, err
	}

	// IsRangeEncoding is 1 bit after MaxVendorID
	isRange := isSet(data, startBit+16)

	// Payload starts after MaxVendorID (16 bits) + IsRangeEncoding (1 bit)
	payloadStart := startBit + 17

	if isRange {
		rs, _, err := parseRangeSection(data, maxVendorID, payloadStart)
		return rs, err
	}

	bf, _, err := parseBitField(data, maxVendorID, payloadStart)
	return bf, err
}

// IsConsentV2 return true if the consent strings looks like a tcf v2 consent string
func IsConsentV2(consent string) bool {
	return len(consent) > 0 && consent[0] == consentStringTCF2Prefix
}
