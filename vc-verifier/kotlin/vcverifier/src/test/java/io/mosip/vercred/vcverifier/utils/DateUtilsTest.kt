package io.mosip.vercred.vcverifier.utils

import io.mosip.vercred.vcverifier.utils.DateUtils.parseDate
import io.mosip.vercred.vcverifier.utils.DateUtils.isValidDate
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue


class DateUtilsTest {

    @Test
    fun testBasicUtcDate() {
        val date = parseDate("2025-09-17T10:15:30Z")
        assertNotNull(date)
        assertEquals(1758104130000L, date?.time)
    }

    @Test
    fun testFractionalSecondsMillis() {
        val date = parseDate("2025-09-17T10:15:30.123Z")
        assertNotNull(date)
        assertEquals(1758104130123L, date?.time)
    }

    @Test
    fun testFractionalSecondsNanoTruncated() {
        val date = parseDate("2025-09-17T10:15:30.123456789Z")
        assertNotNull(date)
        assertEquals(1758104130123, date?.time)
    }

    @Test
    fun testWithPositiveOffset() {
        val utc = parseDate("2025-09-17T10:15:30Z")
        val offset = parseDate("2025-09-17T15:45:30+05:30")
        assertNotNull(offset)
        assertEquals(utc?.time, offset?.time)
    }

    @Test
    fun testWithNegativeOffset() {
        val utc = parseDate("2025-09-17T10:15:30Z")
        val offset = parseDate("2025-09-17T06:15:30-04:00")
        assertNotNull(offset)
        assertEquals(utc?.time, offset?.time)
    }

    @Test
    fun testNoTimezoneTreatedAsUTC() {
        val date = parseDate("2025-09-17T10:15:30")
        val utc = parseDate("2025-09-17T10:15:30Z")
        assertNotNull(date)
        assertEquals(utc?.time, date?.time)
    }

    @Test
    fun testLeapYearValid() {
        val date = parseDate("2024-02-29T12:00:00Z")
        assertNotNull(date)
    }

    @Test
    fun testFractionalSingleDigit() {
        val date = parseDate("2025-09-17T10:15:30.1Z")
        assertNotNull(date)
        assertEquals(1758104130100L, date?.time)
    }

    @Test
    fun testFractionalMaxDigits() {
        val date = parseDate("2025-09-17T10:15:30.987654321Z")
        assertNotNull(date)
        assertEquals(1758104130987, date?.time)
    }

    @Test
    fun testBoundaryOffsetEqualsUtc() {
        val utc = parseDate("2025-09-17T10:15:30Z")
        val offset = parseDate("2025-09-17T10:15:30+00:00")
        assertNotNull(offset)
        assertEquals(utc?.time, offset?.time)
    }


    @Test
    fun testMalformedString_missing_T() {
        assertNull(parseDate("2025-09-17 10:15:30"))
    }

    @Test
    fun testInvalidMonth() {
        assertNull(parseDate("2025-13-01T10:15:30Z"))
    }

    @Test
    fun testInvalidDay() {
        assertNull(parseDate("2025-09-31T10:15:30Z"))
    }

    @Test
    fun testEmptyString() {
        assertNull(parseDate(""))
    }

    @Test
    fun testNonsenseString() {
        assertNull(parseDate("not-a-date"))
    }

    @Test
    fun testLeapYearInvalid() {
        assertNull(parseDate("2023-02-29T12:00:00Z"))
    }


    @Test
    fun testIsValidTrue() {
        assertTrue(isValidDate("2025-09-17T10:15:30Z"))
        assertTrue(isValidDate("2025-09-17T10:15:30.123456+05:30"))
        assertTrue(isValidDate("2025-09-17T10:15:30"))
    }

    @Test
    fun testIsValidFalse() {
        assertFalse(isValidDate(""))
        assertFalse(isValidDate("not-a-date"))
        assertFalse(isValidDate("2025-09-17 10:15:30"))
        assertFalse(isValidDate("2023-02-29T12:00:00Z"))
    }

    @Test
    fun `isIsoMsoDateTime accepts Z full-date-time without fractional seconds`() {
        assertTrue(DateUtils.isIsoMsoDateTime("2024-10-23T07:01:17Z"))
    }

    @Test
    fun `isIsoMsoDateTime rejects fractional seconds and non-Z offsets`() {
        assertFalse(DateUtils.isIsoMsoDateTime("2024-10-23T07:01:17.123Z"))
        assertFalse(DateUtils.isIsoMsoDateTime("2024-10-23T07:01:17+00:00"))
        assertFalse(DateUtils.isIsoMsoDateTime("2024-10-23"))
    }

    @Test
    fun `isIsoFullDate accepts YYYY-MM-DD only`() {
        assertTrue(DateUtils.isIsoFullDate("2024-06-15"))
        assertFalse(DateUtils.isIsoFullDate("2024-06-15T00:00:00Z"))
    }
}
