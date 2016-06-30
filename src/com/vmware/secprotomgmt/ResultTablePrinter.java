/**
 * Utility program to print out the SSL Configuration information
 * for each port in user readable aligned, table format.
 *
 * Copyright (c) 2016
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * @author Gururaja Hegdal (ghegdal@vmware.com)
 * @version 1.0
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

package com.vmware.secprotomgmt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ResultTablePrinter
{
    /**
     * Class variables
     */
    List<List<String>> allLines = new ArrayList<>();
    List<Integer> maximumLen = new ArrayList<>();
    int numCol = -1;

    // All methods
    public ResultTablePrinter addLine(String... line)
    {

        if (numCol == -1) {
            numCol = line.length;
            for(int i = 0; i < numCol; i++) {
                maximumLen.add(0);
            }
        }

        if (numCol != line.length) {
            throw new IllegalArgumentException();
        }

        for(int i = 0; i < numCol; i++) {
            maximumLen.set(i, Math.max( maximumLen.get(i), line[i].length() )  );
        }

        allLines.add( Arrays.asList(line) );

        return this;
    }

    public void print()
    {
        System.out.println(toString());
    }

    @Override
    public String toString()
    {
        String result = "";
        for(List<String> line : allLines) {
            for(int i = 0; i < numCol; i++) {
                result += addPad( line.get(i), maximumLen.get(i) + 1 );
            }
            result += System.lineSeparator();
        }
        return result;
    }

    private String addPad(String word, int newLength)
    {
        while (word.length() < newLength) {
            word += " ";
        }
        return word;
    }
}