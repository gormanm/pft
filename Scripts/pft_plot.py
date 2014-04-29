#!/usr/bin/env python
#
#  Copyright (c) 2006, 2014 SGI. All rights reserved.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Work in Progress:  convert 'ptf to agr data' to "pft_plot" using matplotlib
# TODO:  add 'tabulate' option to emit tabular [averaged] data
#-----------------------------------------------------------------------------
"""
pft_plot.py => plot pft [page fault test] data from multiple pft runs using
matplotlib.

 runpft script runs from 1 to nr_cpus-1 threads.  Possibly multiple runs per
 thread count.  We average these.
	TODO:  compute std dev'n for error bars?

 input file[s] may contain multiple runpft runs--e.g., with different
 parameters--e.g., anon vs shmem, mlock vs touch, ... -- possibly from
 multiple kernels--e.g., with and without patches applied.

 Plot faults/cpu-sec and faults/wall-sec for all data sets with same set of
 pft parameters--e.g., on multiple kernels--on same graph for comparison.
"""
#-----------------------------------------------------------------------------

s_opts = ':hdl:p:v'
l_opts = ['help', 'debug', 'legend_loc=', 'plot=', 'verbose' ]

USAGE=\
"""
Usage:  pft_plot [-hv] [-l <legend-loc>] [-p <plot-select>] <pft-data-file> ...
Where:
\t-h      = Help!  show usage.
\t-v      = Verbose - show what's happening\n
\t-l <legend-loc> - specify legend location; default = 'best'
\t          text locs:  'best' or [{upper|lower|center}-]{right|left}
\t                 or:   [{upper|lower}-]center -- e.g., 'upper-left'
\t                 or:   abbreviations for above:  l, r, c, ul, lc, ...
\t          coordinates:  <x>,<y> as floating point values 0.0..1.0
\t          'none' to omit legend--e.g., when it obscures the plot.
\t-p {[fpcs],[fpws]|[wall],[cpu]} - plot selected pft results [see
\t          header, below]. default:  faults per both cpu & wall secs.
\t          Only one may be selected, except for wallclock and cpu times.
\t<pft-data-file> ...  is a list of zero or more files to convert.
\t          Default is standard input.\n
Plot pft [page fault test -- mempolicy version] results.
Input Format -- one or more of:\n
PLOTID <plot-id> - arbitrary id to group data sets
TITLE <plot-title> -- one per <plot-id>, last one wins.
SUBTITLE <plot-subtitle> -- one per <plot-id>, last one wins.
LEGEND <curve-legend> -- one per data set.  identifies data set and curve
           on the plot.  legends must be different or later occurrences in
           the input stream will overwrite earlier data set[s] with same
           legend.   NOTE:  a 'LEGEND' tag is required to indicate the
           start of results for an PFT run.  pft_plot won't start looking
           for the data header until it sees a 'LEGEND'.
other <annontations, blank lines> -- ignored
  Gb  Thr CLine  User      System   Wall  flt/cpu/s fault/wsec
   N   TT   N    N.NNs      NN.NNs NN.NNs  CCCCC.ccc  WWWWWW.www

Faults/{cpu|wallclock}-seconds or cpu and wall clock time--which ever is
selected--will be averaged for successive lines with same thread count [TT].
The faults/{cpu|wall}-sec or cpu+wall clock time for all LEGENDs with the
same PLOTID will be plotted on the same graph.  This will allow comparison
of fault rate [inversely proportional to allocation overhead], e.g., for
patched and unpatched kernels.
"""

#-----------------------------------------------------------------------------

import getopt, os, sys, inspect
from math import log10

# select the Anti-Grain Geometry engine backend for 'png' output
# Must do this before importing pyplot, ...
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

#-----------------------------------------------------------------------------
# command line options:

verbose 	= False
debug		= False

#=============================================================================

def vprint(msg):
	global verbose
	if bool(verbose):
		print >>sys.stderr, msg
		sys.stderr.flush()

#-----------------------------------------------------------------------------
def usage(ret, msg):
	"""
	emit @msg, if specified, then
	emit program usage and exit with @ret return code
	"""
	if msg:
		print >>sys.stderr, msg
	print >>sys.stderr, USAGE
	sys.stderr.flush()
	sys.exit(ret)

#-----------------------------------------------------------------------------
def warning(msg):
	print >>sys.stderr,'WARNING: ' + msg
	sys.stderr.flush()

#-----------------------------------------------------------------------------
def die(ret, msg):
	"""
	emit FATAL @msg and exit with @ret return code
	"""
	print >>sys.stderr,'FATAL: ' + msg
	sys.stderr.flush()
	sys.exit(ret)

#-----------------------------------------------------------------------------
# usage:  not_implemented_yet(inspect.currentframe())
def not_implemented_yet(frame):
	vprint((inspect.getframeinfo(frame)[2]) + " - not implemented yet")

#=============================================================================

# per plot data sets for PFT:
faults_per_cpu_sec  = []
faults_per_wall_sec = []
user_cpu_sec = []
system_cpu_sec = []
real_time_sec = []

# default
plot_items = ["fpcs", "fpws"]

the_plots = {}	# mapping of test/plot id [pft test parameters] to data_set[s]
#                 each item in list is a dict: {'<legend>': [<fault data>]}
threads   = []   # x-axis values: 1, 2, ... <max-threads>

# plot annotations:
plot_annotations = ("plot_title", "plot_subtitle", "y_label")
plot_title = None
plot_subtitle = None

# for generating multiple plots from same data set/same plotid
# will add non-default 'plot items' to file name.
plot_file_suffix=""

y_axis_labels = {
	'fpcs': "faults/second",
	'fpws': "faults/second",
	'cpu' : "seconds",
	'wall' : "seconds"
}

# legend location:
# {best|[{upper|lower|center} ]{right|left}|{upper|lower} ]center}
# or (float(x),float(y))
legend_loc = 'best'

nr_runs   = None

#=============================================================================
# plot the results:

line_styles = [ '-', '--', '-.', ':' ]
line_colors = [ 'k', 'r', 'g', 'b' ]

fwidth = 9.0
fheight = 6.0

roundup = lambda v, s: s * round(( v + (s-1)) / s)

#-----------------------------------------------------------------------------
def dump_curves(curves):
	if debug:
		vprint("curves:\n " + str(curves))

#-----------------------------------------------------------------------------
def emit_a_plot(plotid, a_plot):
	global plot_file_suffix

	# top level Figure, containing all [sub]plots
	fig = plt.figure(figsize=(fwidth,fheight))

	# single subplot to contain the curves for the pft data
	ax = fig.add_subplot(111, autoscale_on=False)

	# Add figure text for "title"
	title = fig.text(.5, .95,
	                 'Linux Page Fault Test:  ' + a_plot['plot_title'],
	                  horizontalalignment='center')
	title.set_fontsize('large')

	# Use subplot title as subtitle
	axtitle = ax.set_title(a_plot['plot_subtitle'])
	axtitle.set_fontsize('medium')

	# no grid [default?]
	ax.grid(False)

	# axes labels
	ax.set_xlabel("Number of tasks or threads")
	# y axis label specified by the plot
	ax.set_ylabel(a_plot['y_label'])

	# plot the curves in a_plot

	curves = []
	legends = []
	iline = 0
	x_max = 0
	y_max = 0

	# to get all of the curves on a single plot, I *think* I need to pass them
	# via a single call to plot().  So, construct the argument list and pass
	# [below] using the '*args' syntax.
	for legend, data in a_plot.iteritems():
		if legend not in plot_annotations:
			# must be a curve
			x_data, y_data = data
			x_max = max(x_max, max(x_data)) # remember for axes ranges
			y_max = max(y_max, max(y_data))

			vprint("appending legend " + (legend))
			legends.append(legend)
			curves.append(x_data)
			curves.append(y_data)
			curves.append(line_colors[iline % len(line_styles)] +
				      line_styles[iline / len(line_styles)])
			iline += 1

	dump_curves(curves)

	# specify axes ranges for subplot
	y_scale = 10 ** int(log10(y_max))
	y_limit = roundup(y_max, y_scale)
	ax.set_ylim(0, y_limit)

	#x_scale = 10 ** int(log10(x_max))
	#x_limit = roundup(x_max, x_scale)
	# don't round up x-limit
	x_limit = x_max
	ax.set_xlim(0, x_limit)

	the_plot = ax.plot(*curves)

	if legend_loc != 'none':
		# plot the curves on the subplot;
		# returns list of curves/lines for use with legend().
		leg = ax.legend(the_plot, legends, loc=legend_loc, shadow=True)

		# decorate the legend box
		# set legend background color to light gray:
		frame  = leg.get_frame()
		frame.set_facecolor('0.80')

		# adjust legend text font size:
		for t in leg.get_texts():
			t.set_fontsize('small')

		# set the legend line widths:
		for l in leg.get_lines():
			l.set_linewidth(1.5)
	else:
		plot_file_suffix += "-no_legend"

	#TODO:  command line option:  view w/ or w/o save?
	#plt.show()

	filename = "ptf-" + plotid + plot_file_suffix + ".png"
	vprint("saving filename " + filename)
	plt.savefig(filename)

#-----------------------------------------------------------------------------
def emit_the_plots():
	"""
	generate plot for each item in the_plots via matplotlib
	"""
	vprint("final threads[] = " + str(threads))

	for title, a_plot in the_plots.iteritems():
		emit_a_plot(title, a_plot)

#-----------------------------------------------------------------------------
def emit_warnings():
	"""
	emit warnings regarding mismatched data sets, ... now that we've
	read and processed all of the input
	"""

	# TODO:  no longer used.  remove if no other uses arise
	return

#=============================================================================
# debug:  dump plot, data tables

def dump_a_plot(title, a_plot):
	vprint("dump_a_plot:  " + title)

	for legend, data in a_plot.iteritems():
		if legend in plot_annotations:
			vprint(legend + ", " + data)
			continue
		x_data, y_data = data
		vprint("legend:  " + legend)
		vprint("x_data:\n" + str(x_data))
		vprint("y_data:\n" + str(y_data))

	return

#-----------------------------------------------------------------------------
def debug_dump_data(pft_files):
	global debug, verbose

	if not debug:
		return

	saved_verbose = verbose; verbose = True
	vprint("number of files processed: %d" % len(pft_files))
	vprint("number of plots processed: %d" % len(the_plots))

	for title, a_plot in the_plots.iteritems():
		dump_a_plot(title, a_plot)

	verbose = saved_verbose

#-----------------------------------------------------------------------------
plotid = None
legend = None
def start_new_plot(legend):

	global plotid, plot_title, plot_subtitle, threads
	global faults_per_cpu_sec, faults_per_wall_sec, user_cpu_sec, system_cpu_sec, real_time_sec

	if not plotid:
		usage(4, "pft_plot:  no PLOTID specified before LEGEND")

	if plotid not in the_plots:
		the_plots[plotid] = {}	# new plot

	a_plot = the_plots[plotid]

	if not plot_title or not plot_subtitle:
		warning("pft_plot:  no PLOT_[SUB]TITLE specified before LEGEND")

	# last one, if any, wins
	a_plot['plot_title'] = plot_title
	a_plot['plot_subtitle'] = plot_subtitle

	# new data sets for this (plot);  read_pft_data() will populate
	threads = []
	faults_per_cpu_sec  = []
	faults_per_wall_sec = []
	user_cpu_sec = []
	system_cpu_sec = []
	real_time_sec = []

	# add curves for selected plot items.
	# For pft plots, there will always be two for each data set:
	for item in plot_items:
		vprint("parsing item: " + item)
		a_plot["y_label"] = y_axis_labels[item]	# last one wins, but they're the same
		if item == "fpcs":
			a_plot['faults/cpu-sec  : ' + legend] = [threads, faults_per_cpu_sec]
		elif item == "fpws":
			a_plot['faults/wall-sec : ' + legend] = [threads, faults_per_wall_sec]
		elif item == "cpu":
			a_plot['user-cpu-sec : ' + legend] = [threads, user_cpu_sec]
			a_plot['system-cpu-sec : ' + legend] = [threads, system_cpu_sec]
		elif item in ("wall"):
			a_plot['real-time-sec : ' + legend] = [threads, real_time_sec]
		else:
			die(6, "Bogus plot_item ''" + item)

#=============================================================================
# data reduction and preparation:

#-----------------------------------------------------------------------------
def prep_line(line):
	""" trim trailing new line and leading/trailing whitespace from line """
	return line[:-1].lstrip(None).rstrip(None)

#-----------------------------------------------------------------------------
def read_pft_data(pft_file):
	"""
	continue reading pft_file, started in caller [read_ptf_file()] and save
	plot data containing averages of multiple runs at each thread count.
	"""
	global threads, nr_runs

	nrpt = 0	# nr of reports per thread count
	fpcs = 0.0	# faults per cpu sec
	fpws = 0.0	# faults per wall clock sec
	usrcpu = 0.0	# user cpu seconds
	syscpu = 0.0	# system cpu seconds
	realtime = 0.0	# real [wall clock] time.
	prev_threads = 0	# for detecting new thread count

	# N.B., need a blank line to terminate the loop between
	#       multiple sections of a single file
	for line in pft_file:
		line = prep_line(line)
		words = line.split(None) # [gb threads cl us ss ws fpcs fpws]
		if len(words) < 8: break

		#  don't assume sequence 1,2,3...,max
		nr_threads =  int(words[1])
		if nr_threads <= 0:
			die(5, "Bogus input:  nr_threads [%d] <= 0\n" % nr_threads)

		if prev_threads == 0:
			prev_threads = nr_threads
		elif nr_threads != prev_threads:
			# append averages for previous thread count to data set
			if len(threads) == 0 or prev_threads > threads[-1]:
				threads.append(prev_threads)	# x-axis thread counts

			faults_per_cpu_sec.append(float(fpcs) / float(nrpt))
			faults_per_wall_sec.append(float(fpws) / float(nrpt))
			user_cpu_sec.append(float(usrcpu) / float (nrpt))
			system_cpu_sec.append(float(syscpu) / float (nrpt))
			real_time_sec.append(float(realtime) / float(nrpt))

			if nr_runs == None:
				nr_runs = nrpt
			elif nr_runs != nrpt:
				nr_runs_mismatch = True
			nrpt = 0
			fpcs = 0.0
			fpws = 0.0
			usrcpu = 0.0
			syscpu = 0.0
			realtime = 0.0
			prev_threads = nr_threads

		# accumulate runs w/ same thread count for averaging
		fpcs += float(words[6])
		fpws += float(words[7])
		usrcpu += float(words[3].strip("s"))
		syscpu += float(words[4].strip("s"))
		realtime += float(words[5].strip("s"))
		nrpt += 1

	# emit last thread count data, if any
	if nrpt != 0:
		if len(threads) == 0 or prev_threads > threads[-1]:
			threads.append(prev_threads)	# x-axis thread counts

		faults_per_cpu_sec.append(float(fpcs) / float(nrpt))
		faults_per_wall_sec.append(float(fpws) / float(nrpt))
		user_cpu_sec.append(float(usrcpu) / float (nrpt))
		system_cpu_sec.append(float(syscpu) / float (nrpt))
		real_time_sec.append(float(realtime) / float(nrpt))


#-----------------------------------------------------------------------------
def read_annotation(line):
	"""
	read plot annotations:  plotid, title, subtitle, ...
	ignore unrecognized lines
	"""
	global plotid, plot_title, plot_subtitle

	if line.startswith('PLOTID'):
		plotid = line[1+len('PLOTID'):].strip(None)
	elif line.startswith('TITLE'):
		plot_title = line[1+len('TITLE'):].strip(None)
	elif line.startswith('SUBTITLE'):
		plot_subtitle = line[1+len('SUBTITLE'):].strip(None)
	# else ignore

#-----------------------------------------------------------------------------
def expect_what(expected, line, fail):
	if not line.startswith(expected):
		if not fail:
			return False
		else:
			die(2, "Bogus input!  expected '%s', found '%s'"
			% (expected, what))
	return True

#-----------------------------------------------------------------------------
def read_pft_file(pft_file_name):
	"""
	read raw pft data [@pft_file_name] and prepare for plotting
	"""
	vprint("processing " + pft_file_name)

	if pft_file_name == '-':  pft_file = stdin
	else:                     pft_file = open(pft_file_name)

	# if we don't see a 'LEGEND', we'll never look for the header, ...
	# while looking for legend or header, check input for annotations.
	state = 'expect-legend'
	for line in pft_file:
		line = prep_line(line)
		if len(line) == 0:
			continue
		words = line.split(None)
		what  = words[0]

		if state == 'expect-legend':
			if not expect_what('LEGEND', what, False):
				read_annotation(line)
				continue
			legend = line[1+len('LEGEND'):].strip(None)
			if legend in ("y_label", "plot_title", "plot_subtitle"):
				# very unlikely, I hope
				legend += "-pft_plot"	# avoid "keyword" legends
			state = 'expect-header'
		elif state == 'expect-header':
			if not expect_what('Gb', what, False):
				read_annotation(line)
				continue
			start_new_plot(legend)
			read_pft_data(pft_file)
			state = 'expect-legend'
		else:
			die(3, "Bogus state '" + state + "' - program error")

	pft_file.close()

#=============================================================================
#-----------------------------------------------------------------------------
def check_pft_files(pft_files):
	"""
	ensure that all specified pft_files exist and are readable
	"""
	errs = 0

	for pf in pft_files:
		if pf == '-':
			continue
		try:
			if not os.access(pf, os.R_OK):
				vprint("Can't read pft file " + pf)
				errs += 1
		except os.error, msg:
			vprint("Can't find/access pft file " + pf + " - " + msg)
			errs += 1

	if errs:
		die(2, "%d pft file error[s]" % (int(errs)))

#-----------------------------------------------------------------------------
def parse_legend_loc(args):
	"""
		handle the -l/--legend_loc= argument
	"""
	global legend_loc
	vprint("parse_legend_loc\n");

	# Abbreviations/shortcuts for legend location:
	llabbrev = {
	  'b'  : 'best',         'r'  : 'right',         'l'  : 'left',
	  'c'  : 'center',       'cl' : 'center left',   'cr' : 'center right',
	  'ul' : 'upper left',   'uc' : 'upper center',  'ur' : 'upper right',
	  'll' : 'lower left',   'lc' : 'lower center',  'lr' : 'lower right',
	  'n'  : 'none',
	}

	# search for two word locations with ' ' separator, but allow
	# '-' separator in the arg list
	args = args.replace('-', ' ')

	if ',' in args:
		# comma indicates x,y coordinates
		legend_loc = tuple(map(float, args.split(',')))
	elif ' ' in args:
		# two [or more] word long location names with '-' separator
		# e.g., 'upper-left'
		legend_loc = args
	elif  args in llabbrev:
		# shortcut
		legend_loc = llabbrev[args]
	else:
		# assume one word long location name -- e.g., best
		legend_loc = args
	#vprint("legend_loc = " + str(legend_loc))

#-----------------------------------------------------------------------------
def add_plot_item(this_one):
	global plot_items, y_axis_label, plot_file_suffix

	if this_one == 'real':
		this_one = 'wall'

	if this_one not in plot_items:
		plot_items.append(this_one)
		y_axis_label = y_axis_labels[this_one]
		sep = '-'
		if plot_file_suffix:
			sep = '+'
		plot_file_suffix = plot_file_suffix + sep + this_one
		#vprint("plot_file_suffix now: " + plot_file_suffix)


#-----------------------------------------------------------------------------
def parse_plot_list(args):
	global plot_items

	vprint("parse_plot_list:  " + args)

	plot_items = []		# forget the default
	largs = args.split(',')
	plot_faults = False
	plot_seconds = False

	for arg in largs:
		if arg in ("fpcs", "fpws"):
			if plot_seconds:
				print >>sys.stderr, "Can't plot faults and seconds on same plot"
				sys.stderr.flush()
				continue
			add_plot_item(arg)
			plot_faults = True
		elif arg in ("cpu", "wall", "real"):
			if plot_faults:
				print >>sys.stderr, "Can't plot seconds and faults on same plot"
				sys.stderr.flush()
				continue
			add_plot_item(arg)
			plot_seconds = True
		else:
			usage(2, "Bogus plot selection:  " + arg + "\n")

	vprint("plot items = " + str(plot_items) )


#-----------------------------------------------------------------------------
def parse_args(in_args):
	global verbose, debug
	sys.stderr.flush()
	try:
		opts, args = getopt.getopt(in_args, s_opts, l_opts)
	except getopt.GetoptError, msg:
		print >>sys.stderr, msg
		sys.stderr.flush()
		die(1, USAGE)

	sys.stderr.flush()
	for o, a in opts:
		sys.stderr.flush()
		if o in ("-h", "--help"):
			usage(0, '')
		elif o in ("-d", "--debug"):
			debug = True
		elif o in ("-v", "--verbose"):
			verbose = True
		elif o in ("-l", "--legend_loc="):
			parse_legend_loc(a)
		elif o in ("-p", "--plot"):
			parse_plot_list(a)
		else:
			usage(1, "unrecognized option " + o)

	if len(args) < 1:
		args.append('-')

	return args

#=============================================================================
def main():
	print >>sys.stderr, "pft_plot - WIP... "
	sys.stderr.flush()

	pft_files = parse_args(sys.argv[1:])

	check_pft_files(pft_files)

	for pf in pft_files:
		read_pft_file(pf)

	debug_dump_data(pft_files)

	if len(the_plots) > 0:
		emit_warnings()
		emit_the_plots()

#=============================================================================
if __name__ == "__main__":
	main()

