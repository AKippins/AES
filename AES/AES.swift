//
//  AES Encrypt.swift
//  AES Encryption
//
//  Created by Aaron Michael Kippins on 4/4/19.
//  Copyright © 2019 Kippins. All rights reserved.
//

import Foundation
import AppKit


//import java.util.Arrays

/**
 * AEScipher
 *
 *This class holds all of the necessary means for us to do our AES conversion
 * Cipher
 */
public class AEScipher {
    /**
     * This inverse S Box contains all of the values needed for our substitution portion
     * of the cipher
     */
    let inverseSbox = [
        "52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E",
        "81", "F3", "D7", "FB", "7C", "E3", "39", "82", "9B", "2F", "FF", "87",
        "34", "8E", "43", "44", "C4", "DE", "E9", "CB", "54", "7B", "94", "32",
        "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E",
        "08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49",
        "6D", "8B", "D1", "25", "72", "F8", "F6", "64", "86", "68", "98", "16",
        "D4", "A4", "5C", "CC", "5D", "65", "B6", "92", "6C", "70", "48", "50",
        "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84",
        "90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05",
        "B8", "B3", "45", "06", "D0", "2C", "1E", "8F", "CA", "3F", "0F", "02",
        "C1", "AF", "BD", "03", "01", "13", "8A", "6B", "3A", "91", "11", "41",
        "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73",
        "96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8",
        "1C", "75", "DF", "6E", "47", "F1", "1A", "71", "1D", "29", "C5", "89",
        "6F", "B7", "62", "0E", "AA", "18", "BE", "1B", "FC", "56", "3E", "4B",
        "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4",
        "1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59",
        "27", "80", "EC", "5F", "60", "51", "7F", "A9", "19", "B5", "4A", "0D",
        "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF", "A0", "E0", "3B", "4D",
        "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61",
        "17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63",
        "55", "21", "0C", "7D"
    ]
    
    /**
     * This Mul 2 contains all of the values needed for our Mix columns portion
     * of the cipher. I found through reading on the topic that people often just
     * use these table since they simplify the process by doing a lookup instead
     * of the complex math.
     */
    let mul2 = [
        "00", "02", "04", "06", "08", "0A", "0C", "0E", "10", "12", "14", "16",
        "18", "1A", "1C", "1E", "20", "22", "24", "26", "28", "2A", "2C", "2E",
        "30", "32", "34", "36", "38", "3A", "3C", "3E", "40", "42", "44", "46",
        "48", "4A", "4C", "4E", "50", "52", "54", "56", "58", "5A", "5C", "5E",
        "60", "62", "64", "66", "68", "6A", "6C", "6E", "70", "72", "74", "76",
        "78", "7A", "7C", "7E", "80", "82", "84", "86", "88", "8A", "8C", "8E",
        "90", "92", "94", "96", "98", "9A", "9C", "9E", "A0", "A2", "A4", "A6",
        "A8", "AA", "AC", "AE", "B0", "B2", "B4", "B6", "B8", "BA", "BC", "BE",
        "C0", "C2", "C4", "C6", "C8", "CA", "CC", "CE", "D0", "D2", "D4", "D6",
        "D8", "DA", "DC", "DE", "E0", "E2", "E4", "E6", "E8", "EA", "EC", "EE",
        "F0", "F2", "F4", "F6", "F8", "FA", "FC", "FE", "1B", "19", "1F", "1D",
        "13", "11", "17", "15", "0B", "09", "0F", "0D", "03", "01", "07", "05",
        "3B", "39", "3F", "3D", "33", "31", "37", "35", "2B", "29", "2F", "2D",
        "23", "21", "27", "25", "5B", "59", "5F", "5D", "53", "51", "57", "55",
        "4B", "49", "4F", "4D", "43", "41", "47", "45", "7B", "79", "7F", "7D",
        "73", "71", "77", "75", "6B", "69", "6F", "6D", "63", "61", "67", "65",
        "9B", "99", "9F", "9D", "93", "91", "97", "95", "8B", "89", "8F", "8D",
        "83", "81", "87", "85", "BB", "B9", "BF", "BD", "B3", "B1", "B7", "B5",
        "AB", "A9", "AF", "AD", "A3", "A1", "A7", "A5", "DB", "D9", "DF", "DD",
        "D3", "D1", "D7", "D5", "CB", "C9", "CF", "CD", "C3", "C1", "C7", "C5",
        "FB", "F9", "FF", "FD", "F3", "F1", "F7", "F5", "EB", "E9", "EF", "ED",
        "E3", "E1", "E7", "E5"
    ]
    
    /**
     * This Mul 3 contains all of the values needed for our Mix columns portion
     * of the cipher. I found through reading on the topic that people often just
     * use these table since they simplify the process by doing a lookup instead
     * of the complex math.
     */
    let mul3 = [
        "00", "03", "06", "05", "0C", "0F", "0A", "09", "18", "1B", "1E", "1D",
        "14", "17", "12", "11", "30", "33", "36", "35", "3C", "3F", "3A", "39",
        "28", "2B", "2E", "2D", "24", "27", "22", "21", "60", "63", "66", "65",
        "6C", "6F", "6A", "69", "78", "7B", "7E", "7D", "74", "77", "72", "71",
        "50", "53", "56", "55", "5C", "5F", "5A", "59", "48", "4B", "4E", "4D",
        "44", "47", "42", "41", "C0", "C3", "C6", "C5", "CC", "CF", "CA", "C9",
        "D8", "DB", "DE", "DD", "D4", "D7", "D2", "D1", "F0", "F3", "F6", "F5",
        "FC", "FF", "FA", "F9", "E8", "EB", "EE", "ED", "E4", "E7", "E2", "E1",
        "A0", "A3", "A6", "A5", "AC", "AF", "AA", "A9", "B8", "BB", "BE", "BD",
        "B4", "B7", "B2", "B1", "90", "93", "96", "95", "9C", "9F", "9A", "99",
        "88", "8B", "8E", "8D", "84", "87", "82", "81", "9B", "98", "9D", "9E",
        "97", "94", "91", "92", "83", "80", "85", "86", "8F", "8C", "89", "8A",
        "AB", "A8", "AD", "AE", "A7", "A4", "A1", "A2", "B3", "B0", "B5", "B6",
        "BF", "BC", "B9", "BA", "FB", "F8", "FD", "FE", "F7", "F4", "F1", "F2",
        "E3", "E0", "E5", "E6", "EF", "EC", "E9", "EA", "CB", "C8", "CD", "CE",
        "C7", "C4", "C1", "C2", "D3", "D0", "D5", "D6", "DF", "DC", "D9", "DA",
        "5B", "58", "5D", "5E", "57", "54", "51", "52", "43", "40", "45", "46",
        "4F", "4C", "49", "4A", "6B", "68", "6D", "6E", "67", "64", "61", "62",
        "73", "70", "75", "76", "7F", "7C", "79", "7A", "3B", "38", "3D", "3E",
        "37", "34", "31", "32", "23", "20", "25", "26", "2F", "2C", "29", "2A",
        "0B", "08", "0D", "0E", "07", "04", "01", "02", "13", "10", "15", "16",
        "1F", "1C", "19", "1A"
    ]
    
    /**
     * This Mul 9 contains all of the values needed for our Mix columns portion
     * of the cipher. I found through reading on the topic that people often just
     * use these table since they simplify the process by doing a lookup instead
     * of the complex math.
     */
    let mul9 = [
        "00", "09", "12", "1B", "24", "2D", "36", "3F", "48", "41", "5A", "53",
        "6C", "65", "7E", "77", "90", "99", "82", "8B", "B4", "BD", "A6", "AF",
        "D8", "D1", "CA", "C3", "FC", "F5", "EE", "E7", "3B", "32", "29", "20",
        "1F", "16", "0D", "04", "73", "7A", "61", "68", "57", "5E", "45", "4C",
        "AB", "A2", "B9", "B0", "8F", "86", "9D", "94", "E3", "EA", "F1", "F8",
        "C7", "CE", "D5", "DC", "76", "7F", "64", "6D", "52", "5B", "40", "49",
        "3E", "37", "2C", "25", "1A", "13", "08", "01", "E6", "EF", "F4", "FD",
        "C2", "CB", "D0", "D9", "AE", "A7", "BC", "B5", "8A", "83", "98", "91",
        "4D", "44", "5F", "56", "69", "60", "7B", "72", "05", "0C", "17", "1E",
        "21", "28", "33", "3A", "DD", "D4", "CF", "C6", "F9", "F0", "EB", "E2",
        "95", "9C", "87", "8E", "B1", "B8", "A3", "AA", "EC", "E5", "FE", "F7",
        "C8", "C1", "DA", "D3", "A4", "AD", "B6", "BF", "80", "89", "92", "9B",
        "7C", "75", "6E", "67", "58", "51", "4A", "43", "34", "3D", "26", "2F",
        "10", "19", "02", "0B", "D7", "DE", "C5", "CC", "F3", "FA", "E1", "E8",
        "9F", "96", "8D", "84", "BB", "B2", "A9", "A0", "47", "4E", "55", "5C",
        "63", "6A", "71", "78", "0F", "06", "1D", "14", "2B", "22", "39", "30",
        "9A", "93", "88", "81", "BE", "B7", "AC", "A5", "D2", "DB", "C0", "C9",
        "F6", "FF", "E4", "ED", "0A", "03", "18", "11", "2E", "27", "3C", "35",
        "42", "4B", "50", "59", "66", "6F", "74", "7D", "A1", "A8", "B3", "BA",
        "85", "8C", "97", "9E", "E9", "E0", "FB", "F2", "CD", "C4", "DF", "D6",
        "31", "38", "23", "2A", "15", "1C", "07", "0E", "79", "70", "6B", "62",
        "5D", "54", "4F", "46"
    ]
    
    /**
     * This Mul 11 contains all of the values needed for our Mix columns portion
     * of the cipher. I found through reading on the topic that people often just
     * use these table since they simplify the process by doing a lookup instead
     * of the complex math.
     */
    let mul11 = [
        "00", "0B", "16", "1D", "2C", "27", "3A", "31", "58", "53", "4E", "45",
        "74", "7F", "62", "69", "B0", "BB", "A6", "AD", "9C", "97", "8A", "81",
        "E8", "E3", "FE", "F5", "C4", "CF", "D2", "D9", "7B", "70", "6D", "66",
        "57", "5C", "41", "4A", "23", "28", "35", "3E", "0F", "04", "19", "12",
        "CB", "C0", "DD", "D6", "E7", "EC", "F1", "FA", "93", "98", "85", "8E",
        "BF", "B4", "A9", "A2", "F6", "FD", "E0", "EB", "DA", "D1", "CC", "C7",
        "AE", "A5", "B8", "B3", "82", "89", "94", "9F", "46", "4D", "50", "5B",
        "6A", "61", "7C", "77", "1E", "15", "08", "03", "32", "39", "24", "2F",
        "8D", "86", "9B", "90", "A1", "AA", "B7", "BC", "D5", "DE", "C3", "C8",
        "F9", "F2", "EF", "E4", "3D", "36", "2B", "20", "11", "1A", "07", "0C",
        "65", "6E", "73", "78", "49", "42", "5F", "54", "F7", "FC", "E1", "EA",
        "DB", "D0", "CD", "C6", "AF", "A4", "B9", "B2", "83", "88", "95", "9E",
        "47", "4C", "51", "5A", "6B", "60", "7D", "76", "1F", "14", "09", "02",
        "33", "38", "25", "2E", "8C", "87", "9A", "91", "A0", "AB", "B6", "BD",
        "D4", "DF", "C2", "C9", "F8", "F3", "EE", "E5", "3C", "37", "2A", "21",
        "10", "1B", "06", "0D", "64", "6F", "72", "79", "48", "43", "5E", "55",
        "01", "0A", "17", "1C", "2D", "26", "3B", "30", "59", "52", "4F", "44",
        "75", "7E", "63", "68", "B1", "BA", "A7", "AC", "9D", "96", "8B", "80",
        "E9", "E2", "FF", "F4", "C5", "CE", "D3", "D8", "7A", "71", "6C", "67",
        "56", "5D", "40", "4B", "22", "29", "34", "3F", "0E", "05", "18", "13",
        "CA", "C1", "DC", "D7", "E6", "ED", "F0", "FB", "92", "99", "84", "8F",
        "BE", "B5", "A8", "A3"
    ]
    
    /**
     * This Mul 13 contains all of the values needed for our Mix columns portion
     * of the cipher. I found through reading on the topic that people often just
     * use these table since they simplify the process by doing a lookup instead
     * of the complex math.
     */
    let mul13 = [
        "00", "0D", "1A", "17", "34", "39", "2E", "23", "68", "65", "72", "7F",
        "5C", "51", "46", "4B", "D0", "DD", "CA", "C7", "E4", "E9", "FE", "F3",
        "B8", "B5", "A2", "AF", "8C", "81", "96", "9B", "BB", "B6", "A1", "AC",
        "8F", "82", "95", "98", "D3", "DE", "C9", "C4", "E7", "EA", "FD", "F0",
        "6B", "66", "71", "7C", "5F", "52", "45", "48", "03", "0E", "19", "14",
        "37", "3A", "2D", "20", "6D", "60", "77", "7A", "59", "54", "43", "4E",
        "05", "08", "1F", "12", "31", "3C", "2B", "26", "BD", "B0", "A7", "AA",
        "89", "84", "93", "9E", "D5", "D8", "CF", "C2", "E1", "EC", "FB", "F6",
        "D6", "DB", "CC", "C1", "E2", "EF", "F8", "F5", "BE", "B3", "A4", "A9",
        "8A", "87", "90", "9D", "06", "0B", "1C", "11", "32", "3F", "28", "25",
        "6E", "63", "74", "79", "5A", "57", "40", "4D", "DA", "D7", "C0", "CD",
        "EE", "E3", "F4", "F9", "B2", "BF", "A8", "A5", "86", "8B", "9C", "91",
        "0A", "07", "10", "1D", "3E", "33", "24", "29", "62", "6F", "78", "75",
        "56", "5B", "4C", "41", "61", "6C", "7B", "76", "55", "58", "4F", "42",
        "09", "04", "13", "1E", "3D", "30", "27", "2A", "B1", "BC", "AB", "A6",
        "85", "88", "9F", "92", "D9", "D4", "C3", "CE", "ED", "E0", "F7", "FA",
        "B7", "BA", "AD", "A0", "83", "8E", "99", "94", "DF", "D2", "C5", "C8",
        "EB", "E6", "F1", "FC", "67", "6A", "7D", "70", "53", "5E", "49", "44",
        "0F", "02", "15", "18", "3B", "36", "21", "2C", "0C", "01", "16", "1B",
        "38", "35", "22", "2F", "64", "69", "7E", "73", "50", "5D", "4A", "47",
        "DC", "D1", "C6", "CB", "E8", "E5", "F2", "FF", "B4", "B9", "AE", "A3",
        "80", "8D", "9A", "97"
    ]
    
    /**
     * This Mul 14 contains all of the values needed for our Mix columns portion
     * of the cipher. I found through reading on the topic that people often just
     * use these table since they simplify the process by doing a lookup instead
     * of the complex math.
     */
    let mul14 = [
        "00", "0E", "1C", "12", "38", "36", "24", "2A", "70", "7E", "6C", "62",
        "48", "46", "54", "5A", "E0", "EE", "FC", "F2", "D8", "D6", "C4", "CA",
        "90", "9E", "8C", "82", "A8", "A6", "B4", "BA", "DB", "D5", "C7", "C9",
        "E3", "ED", "FF", "F1", "AB", "A5", "B7", "B9", "93", "9D", "8F", "81",
        "3B", "35", "27", "29", "03", "0D", "1F", "11", "4B", "45", "57", "59",
        "73", "7D", "6F", "61", "AD", "A3", "B1", "BF", "95", "9B", "89", "87",
        "DD", "D3", "C1", "CF", "E5", "EB", "F9", "F7", "4D", "43", "51", "5F",
        "75", "7B", "69", "67", "3D", "33", "21", "2F", "05", "0B", "19", "17",
        "76", "78", "6A", "64", "4E", "40", "52", "5C", "06", "08", "1A", "14",
        "3E", "30", "22", "2C", "96", "98", "8A", "84", "AE", "A0", "B2", "BC",
        "E6", "E8", "FA", "F4", "DE", "D0", "C2", "CC", "41", "4F", "5D", "53",
        "79", "77", "65", "6B", "31", "3F", "2D", "23", "09", "07", "15", "1B",
        "A1", "AF", "BD", "B3", "99", "97", "85", "8B", "D1", "DF", "CD", "C3",
        "E9", "E7", "F5", "FB", "9A", "94", "86", "88", "A2", "AC", "BE", "B0",
        "EA", "E4", "F6", "F8", "D2", "DC", "CE", "C0", "7A", "74", "66", "68",
        "42", "4C", "5E", "50", "0A", "04", "16", "18", "32", "3C", "2E", "20",
        "EC", "E2", "F0", "FE", "D4", "DA", "C8", "C6", "9C", "92", "80", "8E",
        "A4", "AA", "B8", "B6", "0C", "02", "10", "1E", "34", "3A", "28", "26",
        "7C", "72", "60", "6E", "44", "4A", "58", "56", "37", "39", "2B", "25",
        "0F", "01", "13", "1D", "47", "49", "5B", "55", "7F", "71", "63", "6D",
        "D7", "D9", "CB", "C5", "EF", "E1", "F3", "FD", "A7", "A9", "BB", "B5",
        "9F", "91", "83", "8D"
    ]
    
    /**
     * This S Box contains all of the values needed for our substitution portion
     * of the cipher
     */
    let sbox = [
        "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B",
        "FE", "D7", "AB", "76", "CA", "82", "C9", "7D", "FA", "59", "47", "F0",
        "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0", "B7", "FD", "93", "26",
        "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15",
        "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2",
        "EB", "27", "B2", "75", "09", "83", "2C", "1A", "1B", "6E", "5A", "A0",
        "52", "3B", "D6", "B3", "29", "E3", "2F", "84", "53", "D1", "00", "ED",
        "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF",
        "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F",
        "50", "3C", "9F", "A8", "51", "A3", "40", "8F", "92", "9D", "38", "F5",
        "BC", "B6", "DA", "21", "10", "FF", "F3", "D2", "CD", "0C", "13", "EC",
        "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73",
        "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14",
        "DE", "5E", "0B", "DB", "E0", "32", "3A", "0A", "49", "06", "24", "5C",
        "C2", "D3", "AC", "62", "91", "95", "E4", "79", "E7", "C8", "37", "6D",
        "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08",
        "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F",
        "4B", "BD", "8B", "8A", "70", "3E", "B5", "66", "48", "03", "F6", "0E",
        "61", "35", "57", "B9", "86", "C1", "1D", "9E", "E1", "F8", "98", "11",
        "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF",
        "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F",
        "B0", "54", "BB", "16"
    ]
    
    /**
     * Similar to the S Box the R Con table holds a lot of the necessary means for
     * us to preform a substitution.
     */
    let rcon = [
        "8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36", "6C",
        "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35", "6A",
        "D4", "B3", "7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD",
        "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A",
        "74", "E8", "CB", "8D", "01", "02", "04", "08", "10", "20", "40", "80",
        "1B", "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6",
        "97", "35", "6A", "D4", "B3", "7D", "FA", "EF", "C5", "91", "39", "72",
        "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC",
        "83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02", "04", "08", "10",
        "20", "40", "80", "1B", "36", "6C", "D8", "AB", "4D", "9A", "2F", "5E",
        "BC", "63", "C6", "97", "35", "6A", "D4", "B3", "7D", "FA", "EF", "C5",
        "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F", "25", "4A", "94",
        "33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB", "8D", "01", "02",
        "04", "08", "10", "20", "40", "80", "1B", "36", "6C", "D8", "AB", "4D",
        "9A", "2F", "5E", "BC", "63", "C6", "97", "35", "6A", "D4", "B3", "7D",
        "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD", "61", "C2", "9F",
        "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A", "74", "E8", "CB",
        "8D", "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36", "6C",
        "D8", "AB", "4D", "9A", "2F", "5E", "BC", "63", "C6", "97", "35", "6A",
        "D4", "B3", "7D", "FA", "EF", "C5", "91", "39", "72", "E4", "D3", "BD",
        "61", "C2", "9F", "25", "4A", "94", "33", "66", "CC", "83", "1D", "3A",
        "74", "E8", "CB", "8D"
    ]
    
    /**
     * AESDecrypt
     *
     * This function is responsible for handling the higher level process of
     * implementing AES. This consists of expanding our key into 11 keys including
     * our original. This allows us to have the 10 keys needed for 128bit aes
     * encryption. From there we preform all but one of our 10 rounds of the
     * following: Nibble Substitution(AESNibbleShift()), Shift Rows(AESShiftRow())
     * , Mix Columns(AESMixColumn()), AddKey(AESStateXOR). Then for the final
     * round we preform: Nibble Substitution(AESNibbleShift()),
     * Shift Rows(AESShiftRow()), AddKey(AESStateXOR) the output should be our
     * encrypted text.
     *
     * @param pTextHex: Our plain text value.
     * @param keyHex: Our initial key.
     * @return
     */
    //    public static String[] AES(String pTextHex, String keyHex){
    func AESDecrypt(pTextHex: String, keyHex: String) -> [String] {
        var outputKey: [String] = Array(repeating: "", count: 1)
        var outputKeys: [String] = AESRoundKeys(hexKey: keyHex).reversed()

        let workingMatrix: [[String]] = toByteMatrixCol(hexString: pTextHex)!
        
        var tmpKey: [[String]]  = AESStateXOR(sKey: workingMatrix, hexKey: toByteMatrixCol(hexString: outputKeys[0])!)
        
        //  Number of rounds needed for AES 128bit encryption.
        let roundLimit: Int = 10
        
        //        for (round: int = 1 round < roundLimit round++){
        for round in 1..<roundLimit{
            print("Round " + String(round))
            print()
            tmpKey = AESInverseShiftRow(inStateHex: tmpKey)
            tmpKey = inverseSBoxLookup(inStateHex: tmpKey)
            tmpKey = AESStateXOR(sKey: toByteMatrixCol(hexString: outputKeys[round])!, hexKey: tmpKey)
            tmpKey = AESInverseMixColumn(inStateHex: tmpKey)
        }
        
        print("Final Round")
        print()
        //  Last Round
        tmpKey = AESInverseShiftRow(inStateHex: tmpKey)
        tmpKey = inverseSBoxLookup(inStateHex: tmpKey)
        tmpKey = AESStateXOR(sKey: tmpKey, hexKey: toByteMatrixCol(hexString: outputKeys[10])!)
        
        //  Formatting the key to be properly output
        var key: String = ""
        
        for column in 0...3{
            key += tmpKey[0][column]
            key += tmpKey[1][column]
            key += tmpKey[2][column]
            key += tmpKey[3][column]
        }
        outputKey[0] = key
        
        print(outputKey[0])
        
        return outputKey
    }
    
    /**
     * AESEncrypt
     *
     * This function is responsible for handling the higher level process of
     * implementing AES. This consists of expanding our key into 11 keys including
     * our original. This allows us to have the 10 keys needed for 128bit aes
     * encryption. From there we preform all but one of our 10 rounds of the
     * following: Nibble Substitution(AESNibbleShift()), Shift Rows(AESShiftRow())
     * , Mix Columns(AESMixColumn()), AddKey(AESStateXOR). Then for the final
     * round we preform: Nibble Substitution(AESNibbleShift()),
     * Shift Rows(AESShiftRow()), AddKey(AESStateXOR) the output should be our
     * encrypted text.
     *
     * @param pTextHex: Our plain text value.
     * @param keyHex: Our initial key.
     * @return
     */
//    public static String[] AES(String pTextHex, String keyHex){
    func AESEncrypt(pTextHex: String, keyHex: String) -> [String] {
        var outputKey: [String] = Array(repeating: "", count: 1)
        var outputKeys:  [String] = AESRoundKeys(hexKey: keyHex)
//        do {
        let workingMatrix: [[String]] = toByteMatrixCol(hexString: pTextHex)!
//        } catch matrixStateError.invalidStringSize {
//            print("String length should be equal to 32.")
//        } catch {
//            print("Logic error. Please check toByteMatrixCol function.")
//        }
        
        var tmpKey: [[String]]  = AESStateXOR(sKey: workingMatrix, hexKey: toByteMatrixCol(hexString: outputKeys[0])!)
        
    
    //  Number of rounds needed for AES 128bit encryption.
        let roundLimit: Int = 10
    
//        for (round: int = 1 round < roundLimit round++){
        for round in 1..<roundLimit{
            print("Round " + String(round))
            print()
            tmpKey = AESNibbleSub(inStateHex: tmpKey)
            tmpKey = AESShiftRow(inStateHex: tmpKey)
            tmpKey = AESMixColumn(inStateHex: tmpKey)
            tmpKey = AESStateXOR(sKey: toByteMatrixCol(hexString: outputKeys[round])!, hexKey: tmpKey)
        }
    
        print("Final Round")
        print()
        //  Last Round
        tmpKey = AESNibbleSub(inStateHex: tmpKey)
        tmpKey = AESShiftRow(inStateHex: tmpKey)
        tmpKey = AESStateXOR(sKey: tmpKey, hexKey: toByteMatrixCol(hexString: outputKeys[10])!)
        
        //  Formatting the key to be properly output
        var key: String = ""
        
        for column in 0...3{
            key += tmpKey[0][column]
            key += tmpKey[1][column]
            key += tmpKey[2][column]
            key += tmpKey[3][column]
        }
        outputKey[0] = key
        
        print(outputKey[0])
        
        return outputKey
    }
    
    func AESFullDecrypt(hexString: String, hexKey: String) -> String {
        var decryptedHex: [String] = []
        
        let arrayOfInputs: [String] = AES.parseHex(input: hexString)
        
        for section in arrayOfInputs {
            let decryptedString: [String] = AES.AESDecrypt(pTextHex: section, keyHex: hexKey)
            decryptedHex.append(decryptedString[0])
        }
        
        print("Decrypted Hex:")
        print(decryptedHex)
        
        var pTextStrings: [String] = []
        
        for x in decryptedHex {
            pTextStrings.append(AES.toPlainText(input: x))
        }
        
        print("Plain Text Strings:")
        print(pTextStrings)
        
        let decoded = AES.assembleStrings(input: pTextStrings)
        
        print("Decoded Message:")
        print(decoded)
        
        let stripped = AES.removePadding(input: decoded)
        
        print("Message With Padding Removed:")
        print(stripped)
        
        return stripped
    }
    
    func AESFullDecryptHex(hexString: String, hexKey: String) -> String {
        var decryptedHex: [String] = []
        
        let arrayOfInputs: [String] = AES.parseHex(input: hexString)
        
        for section in arrayOfInputs {
            let decryptedString: [String] = AES.AESDecrypt(pTextHex: section, keyHex: hexKey)
            decryptedHex.append(decryptedString[0])
        }
        
        print("Decrypted Hex:")
        print(decryptedHex)
        
        var pTextStrings: [String] = []
        
        for x in decryptedHex {
            pTextStrings.append(AES.toPlainText(input: x))
        }
        
        print("Plain Text Strings:")
        print(pTextStrings)
        
        let decoded = AES.assembleStrings(input: pTextStrings)
        
        print("Decoded Message:")
        print(decoded)
        
        let stripped = AES.removePaddingHex(input: decoded)
        
        print("Message With Padding Removed:")
        print(stripped)
        
        return stripped
    }
    
    func AESFullEncrypt(plainText: String, hexKey: String) -> String {
        let output: String = AES.padData(input: plainText)
        
        print("Padded Output:")
        print(output)
        
        let arrayOfInputs: [String] = AES.parseString(input: output)
        
        var hexStrings: [String] = []
        
        for x in arrayOfInputs {
            hexStrings.append(AES.toHexString(input: x))
        }
        
        print("Hex Strings:")
        print(hexStrings)
        
        var encryptedHex: [String] = []
        
        for section in hexStrings {
            let encryptedString: [String] = AES.AESEncrypt(pTextHex: section, keyHex: hexKey)
            encryptedHex.append(encryptedString[0])
        }
        
        print("Encrypted Hex:")
        print(encryptedHex)
        
        let hex = AES.assembleStrings(input: encryptedHex)
        
        print("Assembled Hex:")
        print(hex)
        
        return hex
    }
    
    func AESFullEncryptHex(plainText: String, hexKey: String) -> String {
        let output: String = AES.padDataHex(input: plainText)
        
        print("Padded Output:")
        print(output)
        
        let arrayOfInputs: [String] = AES.parseString(input: output)
        
        var hexStrings: [String] = []
        
        for x in arrayOfInputs {
            hexStrings.append(AES.toHexString(input: x))
        }
        
        print("Hex Strings:")
        print(hexStrings)
        
        var encryptedHex: [String] = []
        
        for section in hexStrings {
            let encryptedString: [String] = AES.AESEncrypt(pTextHex: section, keyHex: hexKey)
            encryptedHex.append(encryptedString[0])
        }
        
        print("Encrypted Hex:")
        print(encryptedHex)
        
        let hex = AES.assembleStrings(input: encryptedHex)
        
        print("Assembled Hex:")
        print(hex)
        
        return hex
    }
    
    /**
     * AESInverseMixColumn
     *
     * For this step we're doing dot multiplication I believe on the table below
     * a given matrix of hex. The values below are the values that we need to
     * preform a Galois field on. This process can be simplified by using mul2 and
     * mul3 tables that are commonly used with AES similar to SBox and RCon.
     * In Galois multiplication things basically work out to be an XOR truth table
     * for Addition and Multiplication. That being said that's what I use to do
     * the multiplication. From there it's just a matter of multiplying correctly.
     *
     * 14 11 13 9
     * 9  14 11 13
     * 13 9  14 11
     * 11 13 9  14
     *
     * @param inStateHex: Input matrix.
     * @return
     */
    //    public static [[String]] AESMixColumn([[String]] inStateHex){
    func AESInverseMixColumn(inStateHex: [[String]]) ->  [[String]]{
        var _: Int = inStateHex.count
        var matrix: [[String]] = Array(repeating: Array(repeating: "", count: 4), count: 4)
        
        matrix[0][0] = xorHexStrings(
            value1: mul14Lookup(input: inStateHex[0][0]),
            value2: mul11Lookup(input: inStateHex[1][0]),
            value3: mul13Lookup(input: inStateHex[2][0]),
            value4: mul9Lookup(input: inStateHex[3][0])
        )
        matrix[1][0] = xorHexStrings(
            value1: mul9Lookup(input: inStateHex[0][0]),
            value2: mul14Lookup(input: inStateHex[1][0]),
            value3: mul11Lookup(input: inStateHex[2][0]),
            value4: mul13Lookup(input: inStateHex[3][0])
        )
        matrix[2][0] = xorHexStrings(
            value1: mul13Lookup(input: inStateHex[0][0]),
            value2: mul9Lookup(input: inStateHex[1][0]),
            value3: mul14Lookup(input: inStateHex[2][0]),
            value4: mul11Lookup(input: inStateHex[3][0])
        )
        matrix[3][0] = xorHexStrings(
            value1: mul11Lookup(input: inStateHex[0][0]),
            value2: mul13Lookup(input: inStateHex[1][0]),
            value3: mul9Lookup(input: inStateHex[2][0]),
            value4: mul14Lookup(input: inStateHex[3][0])
        )
        
        matrix[0][1] = xorHexStrings(
            value1: mul14Lookup(input: inStateHex[0][1]),
            value2: mul11Lookup(input: inStateHex[1][1]),
            value3: mul13Lookup(input: inStateHex[2][1]),
            value4: mul9Lookup(input: inStateHex[3][1])
        )
        matrix[1][1] = xorHexStrings(
            value1: mul9Lookup(input: inStateHex[0][1]),
            value2: mul14Lookup(input: inStateHex[1][1]),
            value3: mul11Lookup(input: inStateHex[2][1]),
            value4: mul13Lookup(input: inStateHex[3][1])
        )
        matrix[2][1] = xorHexStrings(
            value1: mul13Lookup(input: inStateHex[0][1]),
            value2: mul9Lookup(input: inStateHex[1][1]),
            value3: mul14Lookup(input: inStateHex[2][1]),
            value4: mul11Lookup(input: inStateHex[3][1])
        )
        matrix[3][1] = xorHexStrings(
            value1: mul11Lookup(input: inStateHex[0][1]),
            value2: mul13Lookup(input: inStateHex[1][1]),
            value3: mul9Lookup(input: inStateHex[2][1]),
            value4: mul14Lookup(input: inStateHex[3][1])
        )
        
        matrix[0][2] = xorHexStrings(
            value1: mul14Lookup(input: inStateHex[0][2]),
            value2: mul11Lookup(input: inStateHex[1][2]),
            value3: mul13Lookup(input: inStateHex[2][2]),
            value4: mul9Lookup(input: inStateHex[3][2])
        )
        matrix[1][2] = xorHexStrings(
            value1: mul9Lookup(input: inStateHex[0][2]),
            value2: mul14Lookup(input: inStateHex[1][2]),
            value3: mul11Lookup(input: inStateHex[2][2]),
            value4: mul13Lookup(input: inStateHex[3][2])
        )
        matrix[2][2] = xorHexStrings(
            value1: mul13Lookup(input: inStateHex[0][2]),
            value2: mul9Lookup(input: inStateHex[1][2]),
            value3: mul14Lookup(input: inStateHex[2][2]),
            value4: mul11Lookup(input: inStateHex[3][2])
        )
        matrix[3][2] = xorHexStrings(
            value1: mul11Lookup(input: inStateHex[0][2]),
            value2: mul13Lookup(input: inStateHex[1][2]),
            value3: mul9Lookup(input: inStateHex[2][2]),
            value4: mul14Lookup(input: inStateHex[3][2])
        )
        
        matrix[0][3] = xorHexStrings(
            value1: mul14Lookup(input: inStateHex[0][3]),
            value2: mul11Lookup(input: inStateHex[1][3]),
            value3: mul13Lookup(input: inStateHex[2][3]),
            value4: mul9Lookup(input: inStateHex[3][3])
        )
        matrix[1][3] = xorHexStrings(
            value1: mul9Lookup(input: inStateHex[0][3]),
            value2: mul14Lookup(input: inStateHex[1][3]),
            value3: mul11Lookup(input: inStateHex[2][3]),
            value4: mul13Lookup(input: inStateHex[3][3])
        )
        matrix[2][3] = xorHexStrings(
            value1: mul13Lookup(input: inStateHex[0][3]),
            value2: mul9Lookup(input: inStateHex[1][3]),
            value3: mul14Lookup(input: inStateHex[2][3]),
            value4: mul11Lookup(input: inStateHex[3][3])
        )
        matrix[3][3] = xorHexStrings(
            value1: mul11Lookup(input: inStateHex[0][3]),
            value2: mul13Lookup(input: inStateHex[1][3]),
            value3: mul9Lookup(input: inStateHex[2][3]),
            value4: mul14Lookup(input: inStateHex[3][3])
        )
        
        print("Inverse Mix Column:")
        for row in matrix {
            print(row)
        }
        print()
        
        return matrix
    }
    
    /**
     * AESInverseShiftRow
     *
     * This function is responsible for applying a shift to the inputted matrix.
     * The first row doesn't shift. The second row shifts to the right 1.
     * The third row shifts to the right 2. The last row shifts to the right 3 or to
     * the left one. If a byte goes to far it wraps to the other side.
     *
     * @param inStateHex
     * @return
     */
    func AESInverseShiftRow(inStateHex: [[String]]) ->  [[String]] {
        var _: Int = inStateHex.count
        var matrix: [[String]] = Array(repeating: Array(repeating: "", count: 4), count: 4)
        
        matrix[0][0] = inStateHex[0][0]
        matrix[0][1] = inStateHex[0][1]
        matrix[0][2] = inStateHex[0][2]
        matrix[0][3] = inStateHex[0][3]
        
        matrix[1][0] = inStateHex[1][3]
        matrix[1][1] = inStateHex[1][0]
        matrix[1][2] = inStateHex[1][1]
        matrix[1][3] = inStateHex[1][2]
        
        matrix[2][0] = inStateHex[2][2]
        matrix[2][1] = inStateHex[2][3]
        matrix[2][2] = inStateHex[2][0]
        matrix[2][3] = inStateHex[2][1]
        
        matrix[3][0] = inStateHex[3][1]
        matrix[3][1] = inStateHex[3][2]
        matrix[3][2] = inStateHex[3][3]
        matrix[3][3] = inStateHex[3][0]
        
        print("Inverse Shift Rows:")
        for row in matrix{
            print((row))
        }
        print()
        return matrix
    }
    
    /**
     * AESMixColumn
     *
     * For this step we're doing dot multiplication I believe on the table below
     * a given matrix of hex. The values below are the values that we need to
     * preform a Galois field on. This process can be simplified by using mul2 and
     * mul3 tables that are commonly used with AES similar to SBox and RCon.
     * In Galois multiplication things basically work out to be an XOR truth table
     * for Addition and Multiplication. That being said that's what I use to do
     * the multiplication. From there it's just a matter of multiplying correctly.
     *
     * 2 3 1 1
     * 1 2 3 1
     * 1 1 2 3
     * 3 1 1 2
     *
     * @param inStateHex: Input matrix.
     * @return
     */
//    public static [[String]] AESMixColumn([[String]] inStateHex){
    func AESMixColumn(inStateHex: [[String]]) ->  [[String]]{
        var _: Int = inStateHex.count
        var matrix: [[String]] = Array(repeating: Array(repeating: "", count: 4), count: 4)
    
        matrix[0][0] = xorHexStrings(
            value1: mul2Lookup(input: inStateHex[0][0]),
            value2: mul3Lookup(input: inStateHex[1][0]),
            value3: inStateHex[2][0],
            value4: inStateHex[3][0]
        )
        matrix[1][0] = xorHexStrings(
            value1: inStateHex[0][0],
            value2: mul2Lookup(input: inStateHex[1][0]),
            value3: mul3Lookup(input: inStateHex[2][0]),
            value4: inStateHex[3][0]
        )
        matrix[2][0] = xorHexStrings(
            value1: inStateHex[0][0],
            value2: inStateHex[1][0],
            value3: mul2Lookup(input: inStateHex[2][0]),
            value4: mul3Lookup(input: inStateHex[3][0])
        )
        matrix[3][0] = xorHexStrings(
            value1: mul3Lookup(input: inStateHex[0][0]),
            value2: inStateHex[1][0],
            value3: inStateHex[2][0],
            value4: mul2Lookup(input: inStateHex[3][0])
        )
        
        matrix[0][1] = xorHexStrings(
            value1: mul2Lookup(input: inStateHex[0][1]),
            value2: mul3Lookup(input: inStateHex[1][1]),
            value3: inStateHex[2][1],
            value4: inStateHex[3][1]
        )
        matrix[1][1] = xorHexStrings(
            value1: inStateHex[0][1],
            value2: mul2Lookup(input: inStateHex[1][1]),
            value3: mul3Lookup(input: inStateHex[2][1]),
            value4: inStateHex[3][1]
        )
        matrix[2][1] = xorHexStrings(
            value1: inStateHex[0][1],
            value2: inStateHex[1][1],
            value3: mul2Lookup(input: inStateHex[2][1]),
            value4: mul3Lookup(input: inStateHex[3][1])
        )
        matrix[3][1] = xorHexStrings(
            value1: mul3Lookup(input: inStateHex[0][1]),
            value2: inStateHex[1][1],
            value3: inStateHex[2][1],
            value4: mul2Lookup(input: inStateHex[3][1])
        )
        
        matrix[0][2] = xorHexStrings(
            value1: mul2Lookup(input: inStateHex[0][2]),
            value2: mul3Lookup(input: inStateHex[1][2]),
            value3: inStateHex[2][2],
            value4: inStateHex[3][2]
        )
        matrix[1][2] = xorHexStrings(
            value1: inStateHex[0][2],
            value2: mul2Lookup(input: inStateHex[1][2]),
            value3: mul3Lookup(input: inStateHex[2][2]),
            value4: inStateHex[3][2]
        )
        matrix[2][2] = xorHexStrings(
            value1: inStateHex[0][2],
            value2: inStateHex[1][2],
            value3: mul2Lookup(input: inStateHex[2][2]),
            value4: mul3Lookup(input: inStateHex[3][2])
        )
        matrix[3][2] = xorHexStrings(
            value1: mul3Lookup(input: inStateHex[0][2]),
            value2: inStateHex[1][2],
            value3: inStateHex[2][2],
            value4: mul2Lookup(input: inStateHex[3][2])
        )
        
        matrix[0][3] = xorHexStrings(
            value1: mul2Lookup(input: inStateHex[0][3]),
            value2: mul3Lookup(input: inStateHex[1][3]),
            value3: inStateHex[2][3],
            value4: inStateHex[3][3]
        )
        matrix[1][3] = xorHexStrings(
            value1: inStateHex[0][3],
            value2: mul2Lookup(input: inStateHex[1][3]),
            value3: mul3Lookup(input: inStateHex[2][3]),
            value4: inStateHex[3][3]
        )
        matrix[2][3] = xorHexStrings(
            value1: inStateHex[0][3],
            value2: inStateHex[1][3],
            value3: mul2Lookup(input: inStateHex[2][3]),
            value4: mul3Lookup(input: inStateHex[3][3])
        )
        matrix[3][3] = xorHexStrings(
            value1: mul3Lookup(input: inStateHex[0][3]),
            value2: inStateHex[1][3],
            value3: inStateHex[2][3],
            value4: mul2Lookup(input: inStateHex[3][3])
        )
        
        print("Mix Column:")
        for row in matrix {
            print(row)
        }
        print()
    
    return matrix
    }
    
    /**
     * AES Nibble Sub
     *
     * This function simple substitutes the bytes in the matrix give and does an
     * S-Box subtitution on them.
     *
     * @param inStateHex
     * @return
     */
    func AESNibbleSub(inStateHex: [[String]]) ->  [[String]]{
        let matrixLength: Int = inStateHex.count
        var matrix: [[String]] = Array(repeating: Array(repeating: "", count: 4), count: 4)
//        for (int row = 0 row < matrixLength row++){
        for row in 0..<matrixLength{
//    for (int col = 0 col < matrixLength col++){
            for col in 0..<matrixLength{
                let result: String = inStateHex[row][col]
                let hexString: String = sBoxLookup(input: result)
    
                matrix[row][col] = hexString
            }
        }
    
        print("Nibble Sub:")
        for row in matrix{
            print(row)
        }
        print()
        return matrix
    }
    
    /**
     * aesRoundKeys
     *
     * This function is responsible for orchestrating the Cipher on the key that
     * I feed into it.
     *
     * We start by feeding in our key into a 4 x 4 matrix and also putting into
     * our working array.
     *
     * If the colum index j is not a multiple of 4. We XOR the fourth past and
     * last column with respect to j, as denoted in the following equation:
     *
     * w(j) = w(j − 4) ⊕ w(j − 1)
     *
     * If the colum index j is a multiple of 4, this indicates that we are
     * starting a new round i, but we can always know in what round we are by
     * computing i = ⌊j/4⌋ and we proceed as follows:
     *
     * For the construction of w(j) we will use the elements of the previous
     * column w(j − 1) = [w0,j − 1 w1,j − 1 w2,j − 1 w3,j − 1] T =w and store
     * them into a temporary vector wnew.
     *
     * Then we perform a shift to the left as follows:
     * w new = [w1,j − 1 w2,j − 1 w3,j − 1 w0,j − 1]
     *
     * Next we transform each of the four bytes in wnew using an S-box function
     * S(·) (supported by Table 1) as follows
     * wnew = [S(w1,j−1) S(w2,j−1) S(w3,j−1) S(w0,j−1)]T
     *
     * Get the Rcon(i) constant for the i-th round by using the look-up Table 2.
     *
     * Perform an XOR operation using the corresponding round constant obtained
     * in the previous step as follows:
     * wnew = [(Rcon(i) ⊕ S(w1,j−1)) S(w2,j−1) S(w3,j−1) S(w0,j−1)]T .
     *
     * Finally, w(j) can be defined as follows:
     * w(j) = w(j − 4) ⊕ wnew.
     *
     * Every round key is then composed of 4 successive readings of the columns
     * of W. E.g., round zero is composed of w(0), w(1), w(2), and w(3) round
     * one will be composed of w(4), w(5), w(6), and w(7) and so on.
     *
     * @param hexKey: Our 16 byte key
     * @return: Returning an array of our modified keys.
     */
    func AESRoundKeys(hexKey: String) -> [String]{
        var matrix: [[String]] = toByteMatrix(hexString: hexKey)!
        var w: [[String]] = Array(repeating: Array(repeating: "", count: 44), count: 4)
    //  Filling in the first 4 columns with our original key
//    for (int index = 0 index <= 3 index++){
        for index in 0...3{
            w[index][0] = matrix[0][index]
            w[index][1] = matrix[1][index]
            w[index][2] = matrix[2][index]
            w[index][3] = matrix[3][index]
        }
    
    //  Filling in the next 40 by preforming out cipher 10 times
//    for (int index = 4 index <= 43 index++){
        for index in 4...43 {
        //  On non 4th rounds we preform an XOR
            if (index % 4 != 0){
//                for (int row = 0 row <= 3 row++){
                for row in 0...3 {
                    w[row][index] = xorHexStrings(value1: w[row][index - 4], value2: w[row][index - 1])
                }
                //  On every 4th round we follow the set of rules defined in the
                //  comments above the function
            } else if (index % 4 == 0){
                let round: Int = index / 4
                var wNew: [String] = Array(repeating: "", count: 4)
                wNew[0] = xorHexStrings(value1: rConLookup(input: round), value2: sBoxLookup(input: w[1][index - 1]))
                wNew[1] = sBoxLookup(input: w[2][index-1])
                wNew[2] = sBoxLookup(input: w[3][index-1])
                wNew[3] = sBoxLookup(input: w[0][index-1])
            
//                for (int position = 0 position <= 3 position++){
                for position in 0...3 {
                    w[position][index] = xorHexStrings(value1: w[position][index - 4], value2: wNew[position])
                }
            
            } else {
                print("Something's not right here...")
            }
    
        }
    
    //  Putting out the keys into an array that we can pass back
        var outputKeys: [String] = Array(repeating: "", count: 11)
//        for (int keys = 0 keys <= 10 keys++){
        for keys in 0...10{
            var key: String = ""
//        for (int column = keys * 4 column <= (keys * 4) + 3 column++){
            for column in (keys * 4)...(keys * 4) + 3{
                key += w[0][column]
                key += w[1][column]
                key += w[2][column]
                key += w[3][column]
            }
            outputKeys[keys] = key
        }
    
        print("Key Expansion:")
        for row in outputKeys{
            print(row)
        }
        print()
        return outputKeys
    }
    
    /**
     * AESShiftRow
     *
     * This function is responsible for applying a shift to the inputted matrix.
     * The first row doesn't shift. The second row shifts to the left 1.
     * The third row shifts to the left 2. The last row shifts to the left 3 or to
     * the right one. If a byte goes to far it wraps to the other side.
     *
     * @param inStateHex
     * @return
     */
    func AESShiftRow(inStateHex: [[String]]) ->  [[String]] {
        var _: Int = inStateHex.count
        var matrix: [[String]] = Array(repeating: Array(repeating: "", count: 4), count: 4)
    
        matrix[0][0] = inStateHex[0][0]
        matrix[0][1] = inStateHex[0][1]
        matrix[0][2] = inStateHex[0][2]
        matrix[0][3] = inStateHex[0][3]
        
        matrix[1][0] = inStateHex[1][1]
        matrix[1][1] = inStateHex[1][2]
        matrix[1][2] = inStateHex[1][3]
        matrix[1][3] = inStateHex[1][0]
        
        matrix[2][0] = inStateHex[2][2]
        matrix[2][1] = inStateHex[2][3]
        matrix[2][2] = inStateHex[2][0]
        matrix[2][3] = inStateHex[2][1]
        
        matrix[3][0] = inStateHex[3][3]
        matrix[3][1] = inStateHex[3][0]
        matrix[3][2] = inStateHex[3][1]
        matrix[3][3] = inStateHex[3][2]
    
        print("Shift Rows:")
//    for (String[] row: matrix){
        for row in matrix{
            print((row))
        }
        print()
        return matrix
    }
    
    /**
     * AESStateXOR
     *
     * This function is basically xorHexString but applied to 2 matrices.
     *
     * @param sKey
     * @param hexKey
     * @return
     */
    func AESStateXOR(sKey: [[String]], hexKey: [[String]]) -> [[String]] {
        let matrixLength: Int = hexKey.count
        var matrix: [[String]] = Array(repeating: Array(repeating: "", count: 4), count: 4)
//    for (int row = 0 row < matrixLength row++){
        for row in 0..<matrixLength{
//    for (int col = 0 col < matrixLength col++){
            for col in 0..<matrixLength{
                var hexString: String = xorHexStrings(value1: sKey[row][col], value2: hexKey[row][col]).uppercased()
    
    
        if (hexString.count == 1){
            hexString = "0" + hexString
        }
            matrix[row][col] = hexString
        }
    }
    
        print("Add Key State(XOR Matrices):")
//    for (String[] row: matrix){
        for row in matrix{
            print((row))
        }
        print()
        return matrix
    }
    
    func assembleStrings(input: [String]) -> String {
        var assembledString = ""
        print(index)
        for index in input {
            assembledString.append(index)
        }
        
        return assembledString
    }
    
    /**
     * inverseSBoxLookup
     *
     * Searches the inverseSBox table for the hex byte at the given position.
     *
     * @param input: the hex byte to search our table on.
     * @return: designated hex byte.
     */
    func inverseSBoxLookup(inStateHex: [[String]]) -> [[String]] {
        var tmpMatrix: [[String]] = Array(repeating: Array(repeating: "", count: 4), count: 4)
        for col in 0...3 {
            tmpMatrix[0][col] = inverseSbox[Int(inStateHex[0][col], radix: 16)!]
            tmpMatrix[1][col] = inverseSbox[Int(inStateHex[1][col], radix: 16)!]
            tmpMatrix[2][col] = inverseSbox[Int(inStateHex[2][col], radix: 16)!]
            tmpMatrix[3][col] = inverseSbox[Int(inStateHex[3][col], radix: 16)!]
            
            if (tmpMatrix[0][col].count == 1){
                tmpMatrix[0][col] = "0" + tmpMatrix[0][col]
            }
            if (tmpMatrix[1][col].count == 1){
                tmpMatrix[1][col] = "0" + tmpMatrix[0][col]
            }
            if (tmpMatrix[2][col].count == 1){
                tmpMatrix[2][col] = "0" + tmpMatrix[0][col]
            }
            if (tmpMatrix[3][col].count == 1){
                tmpMatrix[3][col] = "0" + tmpMatrix[0][col]
            }
        }
        
        return tmpMatrix
    }
    
    /**
     * sBoxLookup
     *
     * Searches the sBox table for the hex byte at the given position.
     *
     * @param input: the hex byte to search our table on.
     * @return: designated hex byte.
     */
    func mul2Lookup(input: String) -> String {
        var mul2Val: String = mul2[Int(input, radix: 16)!]
        if (mul2Val.count == 1){
            mul2Val = "0" + mul2Val
        }
        return mul2Val
    }
    
    /**
     * sBoxLookup
     *
     * Searches the sBox table for the hex byte at the given position.
     *
     * @param input: the hex byte to search our table on.
     * @return: designated hex byte.
     */
    func mul3Lookup(input: String) -> String {
        var mul3Val: String = mul3[Int(input, radix: 16)!]
        if (mul3Val.count == 1){
            mul3Val = "0" + mul3Val
        }
        return mul3Val
    }
    
    /**
     * sBoxLookup
     *
     * Searches the sBox table for the hex byte at the given position.
     *
     * @param input: the hex byte to search our table on.
     * @return: designated hex byte.
     */
    func mul9Lookup(input: String) -> String {
        var mul9Val: String = mul9[Int(input, radix: 16)!]
        if (mul9Val.count == 1){
            mul9Val = "0" + mul9Val
        }
        return mul9Val
    }
    
    /**
     * sBoxLookup
     *
     * Searches the sBox table for the hex byte at the given position.
     *
     * @param input: the hex byte to search our table on.
     * @return: designated hex byte.
     */
    func mul11Lookup(input: String) -> String {
        var mul11Val: String = mul11[Int(input, radix: 16)!]
        if (mul11Val.count == 1){
            mul11Val = "0" + mul11Val
        }
        return mul11Val
    }
    
    /**
     * sBoxLookup
     *
     * Searches the sBox table for the hex byte at the given position.
     *
     * @param input: the hex byte to search our table on.
     * @return: designated hex byte.
     */
    func mul13Lookup(input: String) -> String {
        var mul13Val: String = mul13[Int(input, radix: 16)!]
        if (mul13Val.count == 1){
            mul13Val = "0" + mul13Val
        }
        return mul13Val
    }
    
    /**
     * sBoxLookup
     *
     * Searches the sBox table for the hex byte at the given position.
     *
     * @param input: the hex byte to search our table on.
     * @return: designated hex byte.
     */
    func mul14Lookup(input: String) -> String {
        var mul14Val: String = mul14[Int(input, radix: 16)!]
        if (mul14Val.count == 1){
            mul14Val = "0" + mul14Val
        }
        return mul14Val
    }
    
    func obtainImageApp () -> String {
        var result = ""
        let image: NSImage? = NSImage.init(contentsOfFile: "/Users/kippins/Desktop/TestImage.jpg")

        if image != nil {
            var rect = NSRect(x: 0, y: 0, width: image!.size.width, height: image!.size.height)
            let cgImage = image!.cgImage(forProposedRect: &rect, context: nil, hints: nil)!
            let bitmapRep = NSBitmapImageRep(cgImage: cgImage)
            
            if let imageData = bitmapRep.representation(using: NSBitmapImageRep.FileType.jpeg, properties: [:]) {
                let len = imageData.count
                
                var bytes = [UInt8].init(repeating: 0, count: len)
                imageData.copyBytes(to: &bytes, count: len)
                
                for i in 0...len - 1 {
                    result += String(format: "%02X", arguments: [bytes[i]])
                }
            }
            
            result = self.AESFullEncryptHex(plainText: result, hexKey: "5468617473206D79204B756E67204675")

            do {
                try result.write(toFile: "/Users/kippins/Desktop/Result.txt", atomically: false, encoding: .utf8)
            } catch {
                
            }
            print("Image Recieved!")
        } else {
            print("No image found.")
        }
        
        var hexBytes: [Int] = []
        var hexByte: String = ""
        var byteComplete: Bool = false
        
        for char in result {
            hexByte.append(char)
            
            if byteComplete {
                let hexValue: Int = Int(hexByte, radix: 16)!
                hexBytes.append(hexValue)
                hexByte = ""
            }
            
            byteComplete = !byteComplete
        }
        
//        let rebuiltImageData: Data = Data.init(bytes: hexBytes, count: hexBytes.count)
        let rebuiltImageNSData: NSData = NSData.init(bytes: hexBytes, length: hexBytes.count)
//        let imageRep = NSBitmapImageRep.init(data: rebuiltImageData)
//        let builtImageData = imageRep?.representation(using: NSBitmapImageRep.FileType.png, properties: [:])
        
//        let fileURL = try! FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: false).appendingPathComponent("test.jpg")
        
//        let imageSize = NSMakeSize(image!.size.width, image!.size.height)
//        let imageWithSize = NSImage.init(size: imageSize)
        
//        let rebuiltImage: NSImage = NSImage.init(data: rebuiltImageData)!
        print("Rebuilding image...")
        rebuiltImageNSData.write(toFile: "/Users/kippins/Desktop/TestImageRebuilt.png", atomically: true)
//        imageWithSize.draw(in: <#T##NSRect#>)
        
//        do {
//            try rebuiltImageData.write(to: fileURL, options: .atomic)
//            try builtImageData!.write(to: fileURL, options: .atomic)
//        } catch {
//
//        }
        
        return result
    }
    
    
    func padData(input: String) -> String {
        let paddingChars: [String] = [
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            ":",
            ";",
            "<",
            "=",
            ">",
            "?"
        ]
        var paddedInputLength: Int = input.count
        var paddedString: String = input
        
        if paddedInputLength % 16 != 0 {
            paddedInputLength = ((paddedInputLength / 16) + 1) * 16
        }
        
        let paddingLength: Int = paddedInputLength - input.count
        
        for _ in input.count..<paddedInputLength {
            paddedString.append(paddingChars[paddingLength])
        }
        
        return paddedString
    }
    
    func padDataHex(input: String) -> String {
        let paddingChars: [String] = [
            "00",
            "01",
            "02",
            "03",
            "04",
            "05",
            "06",
            "07",
            "08",
            "09",
            "10",
            "11",
            "12",
            "13",
            "14",
            "15"
        ]
        var paddedInputLength: Int = input.count
        var paddedString: String = input
        
        if paddedInputLength % 32 != 0 {
            paddedInputLength = ((paddedInputLength / 32) + 1) * 32
        }
        
        let paddingLength: Int = (paddedInputLength - input.count) / 2
        
        for _ in stride(from: input.count, to: paddedInputLength, by: 2) {
            paddedString.append(paddingChars[paddingLength])
        }
        
        return paddedString
    }
    
    func parseHex(input: String) -> [String] {
        let originalInputLength: Int = input.count
        var outputStrings: [String] = []
        let sectionCounts: Int = originalInputLength / 32
        
        for position in 0..<sectionCounts {
            let start = input.index(input.startIndex, offsetBy: (position * 32))
            let end = input.index(input.startIndex, offsetBy: (position + 1) * 32)
            let range = start..<end
            outputStrings.append(String(input[range]))
        }
        
        return outputStrings
    }
    
    func parseString(input: String) -> [String] {
        let originalInputLength: Int = input.count
        var outputStrings: [String] = []
        let sectionCounts: Int = originalInputLength / 16
        
        for position in 0..<sectionCounts {
            let start = input.index(input.startIndex, offsetBy: (position * 16))
            let end = input.index(input.startIndex, offsetBy: (position + 1) * 16)
            let range = start..<end
            outputStrings.append(String(input[range]))
        }
        
        return outputStrings
    }
    
    /**
     * rConLookup
     *
     * Searches the rCon table for the hex byte at the given position.
     *
     * @param input: the current round
     * @return: designated hex byte.
     */
    func rConLookup(input: Int) -> String {
        var rConVal: String = rcon[input]
        if (rConVal.count == 1){
            rConVal = "0" + rConVal
        }
        return rConVal
    }
    
    func removePadding(input: String) -> String {
        let paddingChars: [String: Int] = [
            "0": 0,
            "1": 1,
            "2": 2,
            "3": 3,
            "4": 4,
            "5": 5,
            "6": 6,
            "7": 7,
            "8": 8,
            "9": 9,
            ":": 10,
            ";": 11,
            "<": 12,
            "=": 13,
            ">": 14,
            "?": 15,
        ]
        var strippedString: String = input
        let index = input.index(before: input.endIndex)
        let endCharacter = input[index]
        let last16StartIndex = input.index(input.endIndex, offsetBy: -16)
        let last16EndIndex = input.endIndex
        let last16Chars = input[last16StartIndex..<last16EndIndex]
        if let value = paddingChars[String(endCharacter)] {
            var padding: String = ""
            for _ in 0..<value {
                padding.append(endCharacter)
            }
            
            if String(last16Chars).contains(padding) {
                strippedString = String(input.dropLast(value))
            }
        }
        
        return strippedString
    }
    
    func removePaddingHex(input: String) -> String {
        let paddingChars: [String: Int] = [
            "00": 0,
            "01": 1,
            "02": 2,
            "03": 3,
            "04": 4,
            "05": 5,
            "06": 6,
            "07": 7,
            "08": 8,
            "09": 9,
            "10": 10,
            "11": 11,
            "12": 12,
            "13": 13,
            "14": 14,
            "15": 15,
        ]
        var strippedString: String = input
        let index = input.index(before: input.endIndex)
        let indexBack2 = input.index(input.endIndex, offsetBy: -2)
        let endCharacter = input[indexBack2..<index]
        let last32StartIndex = input.index(input.endIndex, offsetBy: -32)
        let last32EndIndex = input.endIndex
        let last32Chars = input[last32StartIndex..<last32EndIndex]
        if let value = paddingChars[String(endCharacter)] {
            var padding: String = ""
            for _ in 0..<value {
                padding.append(String(endCharacter))
            }
            
            if String(last32Chars).contains(padding) {
                strippedString = String(input.dropLast(value))
            }
        }
        
        return strippedString
    }
    
    /**
     * sBoxLookup
     *
     * Searches the sBox table for the hex byte at the given position.
     *
     * @param input: the hex byte to search our table on.
     * @return: designated hex byte.
     */
    func sBoxLookup(input: String) -> String {
        var sBoxVal: String = sbox[Int(input, radix: 16)!]
        if (sBoxVal.count == 1){
            sBoxVal = "0" + sBoxVal
        }
        return sBoxVal
    }
    
    /**
     * toByteMatrix
     *
     * Converts a 128 bit string into a 4 x 4 byte matrix
     *
     * @param hexString: Our 16 Byte Key
     * @return: Returns a 4 x 4 array
     */
    func toByteMatrix(hexString: String) -> [[String]]? {
        if (hexString.count != 32){
            return nil
        }
    
        var matrix: [[String]] = Array(repeating: Array(repeating: "", count: 4), count: 4)
        var byteCompleted: Bool = false
        var row: Int = 0
        var col: Int = 0
        var nextByte: String = ""
    
//    for (int pointer = 0 pointer <= 31 pointer++){
        for pointer in 0...31{
            let index = hexString.index(hexString.startIndex, offsetBy: pointer)
            nextByte += String(hexString[index])
//            nextByte += hexString.charAt(pointer)
            
            if (byteCompleted){
                matrix[row][col] = nextByte
                col += 1
                nextByte = ""
            }
            
            byteCompleted = !byteCompleted
            
            if (col >= 4){
                row += 1
                col = 0
            }
    
    }
    
        print("To Byte Matrix:")
//    for (String[] line: matrix){
        for line in matrix{
            print(line)
        }
            print()
            return matrix
        }
    
    /**
     * toByteMatrixCol
     *
     * Converts a 128 bit string into a 4 x 4 byte matrix
     *
     * @param hexString: Our 16 Byte Key
     * @return: Returns a 4 x 4 array
     */
    func toByteMatrixCol(hexString: String) -> [[String]]? {
    if (hexString.count != 32){
        return nil
        //        throw matrixStateError.invalidStringSize
    }
    
        var matrix: [[String]] = Array(repeating: Array(repeating: "", count: 4), count: 4)
        var byteCompleted: Bool = false
        var row: Int = 0
        var col: Int = 0
        var nextByte: String = ""
    
//    for (int pointer = 0 pointer <= 31 pointer++){
        for pointer in 0...31{
            let index = hexString.index(hexString.startIndex, offsetBy: pointer)
            nextByte += String(hexString[index])
                //hexString.charAt(pointer)
            
            if (byteCompleted){
                matrix[row][col] = nextByte
                row += 1
                nextByte = ""
            }
            
            byteCompleted = !byteCompleted
            
            if (row >= 4){
                col += 1
                row = 0
            }
    
        }
    
    print("To Byte Matrix Col:")
//    for (String[] line: matrix){
        for line in matrix{
            print((line))
        }
        print()
        return matrix
    }
    
    func toHexString(input: String) -> String {
        let data = Data(input.utf8)
        let hexString = data.map{ String(format:"%02x", $0) }.joined()
        
        return hexString
    }
    
    func toPlainText(input: String) -> String {
        var plainText: String = ""
        var hexByte: String = ""
        var byteComplete: Bool = false
        
        for index in 0..<input.count {
            let charPosition = input.index(input.startIndex, offsetBy: index)
            hexByte.append(input[charPosition])
            
            if byteComplete {
                let hexValue: Int = Int(hexByte, radix: 16)!
                let letter: String = String(UnicodeScalar(hexValue)!)
                plainText.append(letter)
                hexByte = ""
            }
            
            byteComplete = !byteComplete
        }
        
        return plainText
    }
    

    
    /**
     * xorHexStrings
     *
     * Preforms an XOR on 2 hex bytes.
     *
     * @param value1: Byte 1
     * @param value2: Byte 2
     * @return: A hex byte
     */
    func xorHexStrings(value1: String, value2: String) -> String {
        let result: Int = Int(value1, radix: 16)! ^ Int(value2, radix: 16)!
        var hexString: String = String(format:"%02X", result)
            //Integer.toHexString(result).toUpperCase()
        if (hexString.count == 1){
            hexString = "0" + hexString
        }
    return hexString
    }
    
    /**
     * xorHexStrings
     *
     * Preforms an XOR on 2 hex bytes.
     *
     * @param value1: Byte 1
     * @param value2: Byte 2
     * @param value3: Byte 3
     * @param value4: Byte 4
     * @return: A hex byte
     */
    func xorHexStrings(value1: String, value2: String, value3: String, value4: String) -> String {
        let result: Int = Int(value1, radix: 16)!
        ^ Int(value2, radix: 16)!
        ^ Int(value3, radix: 16)!
        ^ Int(value4, radix: 16)!
        var hexString: String = String(format:"%02X", result)
            //Integer.toHexString(result).uppercased()
        if (hexString.count == 1){
            hexString = "0" + hexString
        }
        return hexString
    }
}

enum matrixStateError: Error {
    case invalidStringSize
}

//extension String {
//    var hexadecimal: Data? {
//        var data: Data = Data(capacity: characters.count / 2)
//
//        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
//        regex.enumerateMatches(in: self, range: NSRange(startIndex..., in: self)) { match, _, _ in
//        let byteString = (self as NSString).substring(with: match!.range)
//        let num = UInt8(byteString, radix: 16)!
//        data.append(num)
//        }
//
//        guard data.count > 0 else { return nil }
//
//        return data
//    }
//}
//
//extension Data {
//    var hexadecimal: String {
//        return map {}
//    }
//}
