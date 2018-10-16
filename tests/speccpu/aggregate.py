"""
    Use this script to aggregate and analyze the data
"""

import argparse
import json

import numpy as np
from scipy.stats import gmean

def extract_time(run_result):
    if args.time == 'user':
        return run_result[0]
    if args.time == 'system':
        return run_result[1]
    return run_result[0] + run_result[1]


def aggregate(run_results):
    if args.aggregation == 'worst':
        return np.max(run_results)
    if args.aggregation == 'mean':
        return np.mean(run_results)
    if args.aggregation == 'median':
        return np.median(run_results)
    if len(run_results) <= 2:
        return np.max(run_results)
    return np.median(run_results)

def filter(ratio, data):
    if args.filter is not None:
        print(f'Filter out {args.filter}')
        filters = np.ones(len(data), dtype=bool)
        for i, benchmark in enumerate(data.keys()):
            if benchmark in args.filter:
                filters[i] = 0

        return ratio[filters]

    return ratio

def main():
    with open(args.data) as file:
        data = json.load(file)

    result = np.zeros((2, len(data)))
    for i, group in enumerate(['original', 'hase']):
        for j, benchmark in enumerate(data):
            result[i, j] = aggregate(
                [np.sum([extract_time(run_results) for run_results in run['result']])
                    for run in data[benchmark][group]]
            )

    ratio = result[1] / result[0]

    filtered_ratio = filter(ratio, data)

    print('ben\toriginal\thase\tratio')
    for i, benchmark in enumerate(data):
        print(f'{benchmark}\t{result[0, i]:8f}\t{result[1, i]:8f}\t{ratio[i]:.4f}')

    print(f'000\t\t\t\t\t{gmean(filtered_ratio):.4f}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'data',
        type=str,
        help='The json file that holds the result'
    )
    parser.add_argument(
        '--time',
        type=str,
        default='overall',
        choices=['overall', 'user', 'system'],
        help='Choose a time metric'
    )
    parser.add_argument(
        '-a',
        '--aggregation',
        type=str,
        default='auto',
        choices=['auto', 'median', 'worst', 'mean'],
        help='Choose a way to aggregate the data from different runs'
    )
    parser.add_argument(
        '-f',
        '--filter',
        type=str,
        help='Abnormal suites'
    )
    args = parser.parse_args()
    main()