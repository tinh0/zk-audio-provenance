import { useState } from 'react';
import { Crop, Palette, Volume2, Scissors, Headphones, Waves, SlidersHorizontal, AudioLines, Combine, PanelLeft } from 'lucide-react';
import type {
  MediaType, Transformation, PCSType, GnarkBackend, ProverEngine, TransformParams,
  GainParams, CombineParams, PanParams, TremoloParams,
} from '../../types';
import {
  IMAGE_TRANSFORMATIONS, AUDIO_TRANSFORMATIONS, FLOAT32_AUDIO_TRANSFORMATIONS,
  PCS_OPTIONS, GNARK_BACKEND_OPTIONS, requiresStereoInput,
} from '../../types';

interface TransformationSelectorProps {
  mediaType: MediaType;
  isFloat32: boolean; // true if the uploaded WAV is 32-bit float
  isStereo: boolean;  // true if the uploaded WAV is stereo
  onSubmit: (transformation: Transformation, engine: ProverEngine, pcs?: PCSType, gnarkBackend?: GnarkBackend, params?: TransformParams) => void;
  disabled?: boolean;
}

const transformDescriptions: Record<string, string> = {
  crop: 'Extract the top-left half of the image',
  grayscale: 'Convert color image to grayscale',
  mono: 'Convert stereo audio to mono (average L+R)',
  volume: 'Adjust audio volume by a factor',
  trim: 'Extract a sample range from the audio',
  gain: 'Multiply all samples by a constant gain',
  fade_in: 'Linear fade from silence to full volume',
  fade_out: 'Linear fade from full volume to silence',
  combine: 'Mix two tracks with weighted blending',
  pan: 'Adjust stereo left/right balance',
  tremolo: 'Periodic amplitude modulation (wobble)',
};

export function TransformationSelector({
  mediaType,
  isFloat32,
  isStereo,
  onSubmit,
  disabled,
}: TransformationSelectorProps) {
  // Determine which engine + transformations to show
  const engine: ProverEngine = mediaType === 'image' ? 'hyperveritas'
    : isFloat32 ? 'gnark' : 'hyperveritas';

  const transformations: Transformation[] = mediaType === 'image'
    ? IMAGE_TRANSFORMATIONS
    : isFloat32
      ? FLOAT32_AUDIO_TRANSFORMATIONS
      : AUDIO_TRANSFORMATIONS;

  const [selected, setSelected] = useState<Transformation>(transformations[0]);
  const [pcs, setPcs] = useState<PCSType>('brakedown');
  const [gnarkBackend, setGnarkBackend] = useState<GnarkBackend>('groth16');

  // Float32 transform params
  const [gainFactor, setGainFactor] = useState(0.75);
  const [combineAlpha, setCombineAlpha] = useState(0.5);
  const [panValue, setPanValue] = useState(0.0);
  const [tremoloRate, setTremoloRate] = useState(5.0);
  const [tremoloDepth, setTremoloDepth] = useState(0.5);

  // Integer audio params
  const [volumeFactor, setVolumeFactor] = useState(0.5);
  const [trimStart, setTrimStart] = useState(0);
  const [trimEnd, setTrimEnd] = useState(8192);

  const handleSubmit = () => {
    let params: TransformParams = {};

    switch (selected) {
      case 'volume':
        params = { factor: volumeFactor };
        break;
      case 'trim':
        params = { startSample: trimStart, endSample: trimEnd };
        break;
      case 'gain':
        params = { factor: gainFactor } as GainParams;
        break;
      case 'combine':
        params = { alpha: combineAlpha } as CombineParams;
        break;
      case 'pan':
        params = { pan: panValue } as PanParams;
        break;
      case 'tremolo':
        params = { rateHz: tremoloRate, depth: tremoloDepth } as TremoloParams;
        break;
    }

    onSubmit(
      selected,
      engine,
      engine === 'hyperveritas' ? pcs : undefined,
      engine === 'gnark' ? gnarkBackend : undefined,
      params,
    );
  };

  // Check if a float32 transform is disabled due to stereo requirement
  const isTransformDisabled = (t: Transformation) => {
    if (isFloat32 && requiresStereoInput(t as any) && !isStereo) return true;
    if (!isFloat32 && t === 'mono' && !isStereo) return true;
    return false;
  };

  return (
    <div className="space-y-6">
      {/* Engine indicator */}
      <div className="flex items-center gap-2">
        <span className={`badge ${engine === 'gnark' ? 'badge-secondary' : 'badge-primary'}`}>
          {engine === 'gnark' ? 'gnark (Go) - Float32' : 'HyperVerITAS (Rust)'}
        </span>
        {isFloat32 && (
          <span className="text-xs text-base-content/60">
            32-bit float WAV detected - using zk-Location float32 circuits
          </span>
        )}
        {!isFloat32 && mediaType === 'audio' && (
          <span className="text-xs text-base-content/60">
            PCM WAV detected - using HyperVerITAS integer circuits
          </span>
        )}
      </div>

      {/* Transformation Selection */}
      <div>
        <h3 className="text-lg font-semibold mb-3">Select Transformation</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {transformations.map(t => {
            const tdisabled = isTransformDisabled(t);
            return (
              <label
                key={t}
                className={`card cursor-pointer transition-all border-2 ${
                  tdisabled ? 'opacity-40 cursor-not-allowed' :
                  selected === t ? 'border-primary bg-primary/5' : 'border-base-300 hover:border-primary/30'
                }`}
              >
                <div className="card-body p-4 flex-row items-center gap-3">
                  <input
                    type="radio"
                    name="transformation"
                    className="radio radio-primary"
                    checked={selected === t}
                    onChange={() => !tdisabled && setSelected(t)}
                    disabled={tdisabled}
                  />
                  <div>
                    <div className="font-medium capitalize">{t.replace('_', ' ')}</div>
                    <div className="text-xs text-base-content/60">
                      {transformDescriptions[t]}
                      {tdisabled && ' (requires stereo input)'}
                    </div>
                  </div>
                </div>
              </label>
            );
          })}
        </div>
      </div>

      {/* Transformation Parameters */}
      {selected === 'crop' && (
        <div className="card bg-base-200">
          <div className="card-body p-4">
            <h4 className="font-medium mb-1">Crop</h4>
            <p className="text-sm text-base-content/60">
              Extracts the top-left half of the image. The prover proves this region
              was taken from the original without modification.
            </p>
          </div>
        </div>
      )}

      {selected === 'volume' && (
        <div className="card bg-base-200">
          <div className="card-body p-4">
            <h4 className="font-medium mb-2">Volume Factor: {volumeFactor.toFixed(2)}x</h4>
            <input type="range" className="range range-primary" min={0.1} max={2.0} step={0.1}
              value={volumeFactor} onChange={e => setVolumeFactor(+e.target.value)} />
            <div className="flex justify-between text-xs text-base-content/60 px-1">
              <span>0.1x</span><span>1.0x</span><span>2.0x</span>
            </div>
          </div>
        </div>
      )}

      {selected === 'trim' && (
        <div className="card bg-base-200">
          <div className="card-body p-4">
            <h4 className="font-medium mb-2">Trim Range</h4>
            <div className="grid grid-cols-2 gap-3">
              <label className="form-control">
                <span className="label-text text-xs">Start Sample</span>
                <input type="number" className="input input-bordered input-sm" value={trimStart} onChange={e => setTrimStart(+e.target.value)} min={0} />
              </label>
              <label className="form-control">
                <span className="label-text text-xs">End Sample</span>
                <input type="number" className="input input-bordered input-sm" value={trimEnd} onChange={e => setTrimEnd(+e.target.value)} min={1} />
              </label>
            </div>
          </div>
        </div>
      )}

      {selected === 'gain' && (
        <div className="card bg-base-200">
          <div className="card-body p-4">
            <h4 className="font-medium mb-2">Gain Factor: {gainFactor.toFixed(2)}x</h4>
            <input type="range" className="range range-secondary" min={0.0} max={2.0} step={0.05}
              value={gainFactor} onChange={e => setGainFactor(+e.target.value)} />
            <div className="flex justify-between text-xs text-base-content/60 px-1">
              <span>0.0 (silence)</span><span>1.0 (unity)</span><span>2.0 (boost)</span>
            </div>
          </div>
        </div>
      )}

      {selected === 'combine' && (
        <div className="card bg-base-200">
          <div className="card-body p-4">
            <h4 className="font-medium mb-2">Mix Alpha: {combineAlpha.toFixed(2)}</h4>
            <input type="range" className="range range-secondary" min={0.0} max={1.0} step={0.05}
              value={combineAlpha} onChange={e => setCombineAlpha(+e.target.value)} />
            <div className="flex justify-between text-xs text-base-content/60 px-1">
              <span>0.0 (100% R)</span><span>0.5 (50/50)</span><span>1.0 (100% L)</span>
            </div>
          </div>
        </div>
      )}

      {selected === 'pan' && (
        <div className="card bg-base-200">
          <div className="card-body p-4">
            <h4 className="font-medium mb-2">Pan: {panValue.toFixed(2)}</h4>
            <input type="range" className="range range-secondary" min={-1.0} max={1.0} step={0.1}
              value={panValue} onChange={e => setPanValue(+e.target.value)} />
            <div className="flex justify-between text-xs text-base-content/60 px-1">
              <span>-1.0 (full left)</span><span>0.0 (center)</span><span>1.0 (full right)</span>
            </div>
          </div>
        </div>
      )}

      {selected === 'tremolo' && (
        <div className="card bg-base-200">
          <div className="card-body p-4">
            <h4 className="font-medium mb-2">Tremolo</h4>
            <div className="grid grid-cols-2 gap-3">
              <label className="form-control">
                <span className="label-text text-xs">Rate (Hz): {tremoloRate}</span>
                <input type="range" className="range range-secondary range-sm" min={1} max={20} step={1}
                  value={tremoloRate} onChange={e => setTremoloRate(+e.target.value)} />
              </label>
              <label className="form-control">
                <span className="label-text text-xs">Depth: {tremoloDepth.toFixed(2)}</span>
                <input type="range" className="range range-secondary range-sm" min={0.0} max={1.0} step={0.05}
                  value={tremoloDepth} onChange={e => setTremoloDepth(+e.target.value)} />
              </label>
            </div>
          </div>
        </div>
      )}

      {/* Backend / PCS Selection */}
      {engine === 'hyperveritas' ? (
        <div>
          <h3 className="text-lg font-semibold mb-3">Polynomial Commitment Scheme</h3>
          <select className="select select-bordered w-full" value={pcs}
            onChange={e => setPcs(e.target.value as PCSType)}>
            {PCS_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      ) : (
        <div>
          <h3 className="text-lg font-semibold mb-3">Proving Backend</h3>
          <select className="select select-bordered w-full" value={gnarkBackend}
            onChange={e => setGnarkBackend(e.target.value as GnarkBackend)}>
            {GNARK_BACKEND_OPTIONS.map(opt => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Submit */}
      <button className="btn btn-primary btn-block btn-lg" onClick={handleSubmit} disabled={disabled}>
        Generate Proof
      </button>
    </div>
  );
}
